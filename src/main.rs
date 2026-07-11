mod config;
mod event_loop;
mod fake_dns;
mod fd_passing;
mod namespace;
mod proxy;
mod rule;
mod tun;

use std::ffi::CString;
use std::os::unix::io::{BorrowedFd, IntoRawFd, RawFd};

use anyhow::{Context, Result, bail};
use clap::Parser;
use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{ForkResult, Pid, close, execvp, fork, read, write};
use tracing::Level;

use config::Config;
use proxy::ProxyConfig;
use rule::RuleMatcher;

// ── CLI ───────────────────────────────────────────────────────────────────────

/// nsproxy — run a command inside a dedicated network namespace whose traffic
/// is transparently proxied.
///
/// Examples:
///   nsproxy curl http://example.com
///   nsproxy -x socks5://127.0.0.1:1080 curl http://example.com
///   nsproxy -x http://user:pass@proxy.example.com:8080 wget example.com
///   nsproxy -r cidr:10.0.0.0/8=direct curl http://example.com
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Default route: direct, socks5://[user:pass@]host:port, or
    /// http://[user:pass@]host:port
    #[arg(short = 'x', long = "proxy", default_value = "socks5://127.0.0.1:1080")]
    proxy: String,

    /// Routing rule. Repeatable. Format: `<kind>:<value>=<proxy>`, where proxy
    /// is `direct` or a supported proxy URL.
    ///
    /// Examples:
    ///   -r ip:1.2.3.4=direct
    ///   -r cidr:10.0.0.0/8=socks5://127.0.0.1:1081
    ///   -r domain:example.com=http://127.0.0.1:8080
    #[arg(
        short = 'r',
        long = "rule",
        value_name = "RULE",
        action = clap::ArgAction::Append
    )]
    rules: Vec<String>,

    /// Bind-mount a file inside the mount namespace. Repeatable. Format:
    /// `<src>:<dst>`; relative paths are resolved from the current directory.
    #[arg(
        short = 'b',
        long = "bind",
        value_name = "SRC:DST",
        action = clap::ArgAction::Append
    )]
    binds: Vec<String>,

    /// Enable log output; repeat for trace-level logs
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    verbose: u8,

    /// Suppress all log output
    #[arg(short = 'q', long = "quiet")]
    quiet: bool,

    /// Command to run inside the namespace (and its arguments)
    #[arg(trailing_var_arg = true, required = true)]
    command: Vec<String>,
}

#[cfg(test)]
mod cli_tests {
    use super::*;

    #[test]
    fn bind_option_is_repeatable_before_command() {
        let cli = Cli::try_parse_from([
            "nsproxy", "-b", "a:b", "--bind", "c:d", "command", "-b", "argument",
        ])
        .unwrap();

        assert_eq!(cli.binds, ["a:b", "c:d"]);
        assert_eq!(cli.command, ["command", "-b", "argument"]);
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let cli = Cli::parse();

    // --- tracing init --------------------------------------------------------
    let log_level = if cli.quiet || cli.verbose == 0 {
        None
    } else {
        Some(match cli.verbose {
            1 => Level::DEBUG,
            _ => Level::TRACE,
        })
    };

    if let Some(level) = log_level {
        tracing_subscriber::fmt()
            .with_max_level(level)
            .with_target(false)
            .init();
    }

    // --- build Config --------------------------------------------------------
    let default_proxy = ProxyConfig::parse(&cli.proxy).context("parse --proxy")?;
    let rules = RuleMatcher::from_specs(&cli.rules).context("parse --rule")?;
    let cwd = std::env::current_dir().context("get current directory")?;
    let bind_mounts = namespace::parse_bind_mounts(&cli.binds, &cwd).context("parse --bind")?;

    let config = Config {
        default_proxy,
        bind_mounts,
        command: cli.command.clone(),
        rules,
    };
    tracing::debug!(?config, "parsed configuration");

    // --- socketpair ----------------------------------------------------------
    // One socket for fd passing (child → parent: TUN fd).
    // A second byte channel (parent → child: "ready" signal) can ride on the
    // same socket since we do the fd transfer before the ready byte.
    let (parent_sock, child_sock) = socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None,
        SockFlag::SOCK_CLOEXEC,
    )
    .context("socketpair")?;

    // Take ownership of the raw fds so OwnedFd won't auto-close them.
    // We manage their lifetime manually.
    let parent_sock_fd: RawFd = parent_sock.into_raw_fd();
    let child_sock_fd: RawFd = child_sock.into_raw_fd();

    // --- fork ----------------------------------------------------------------
    // SAFETY: fork() is safe here — we are single-threaded at this point (no
    // tokio runtime has been started yet).
    let fork_result = unsafe { fork() }.context("fork")?;

    match fork_result {
        // ── Child ─────────────────────────────────────────────────────────
        ForkResult::Child => {
            // Close the parent-side socket in this process.
            let _ = close(parent_sock_fd);

            match child_main(child_sock_fd, &config) {
                Ok(code) => std::process::exit(code),
                Err(e) => {
                    eprintln!("nsproxy: {:#}", e);
                    std::process::exit(1);
                }
            }
        }

        // ── Parent ────────────────────────────────────────────────────────
        ForkResult::Parent { child } => {
            // Close the child-side socket in this process.
            let _ = close(child_sock_fd);

            parent_main(parent_sock_fd, child, config)?;
            Ok(())
        }
    }
}

// ── Child logic ───────────────────────────────────────────────────────────────

fn child_main(sock: RawFd, config: &Config) -> Result<i32> {
    tracing::debug!("child: setting up namespace");

    // 1. Enter a new network namespace (with user-ns fallback for non-root).
    let needs_maps = namespace::create_namespace().context("create_namespace")?;

    // 2. Signal parent: "I've unshared" — send 1 byte indicating whether maps are needed.
    let signal_byte = if needs_maps { 1u8 } else { 0u8 };
    let sock_bfd = unsafe { BorrowedFd::borrow_raw(sock) };
    write(sock_bfd, &[signal_byte]).context("signal parent after unshare")?;

    // 3. Wait for parent to write uid/gid maps (if needed).
    if needs_maps {
        tracing::debug!("child: waiting for parent to write id maps");
        let mut ack = [0u8; 1];
        read(sock, &mut ack).context("read maps-done ack")?;
        tracing::debug!("child: id maps written by parent");
    }

    // 4. Bring up loopback inside the new netns.
    namespace::bringup_loopback().context("bringup_loopback")?;

    // 5. Create tun0 and configure it.
    let tun_fd: RawFd = namespace::create_tun().context("create_tun")?;

    // 6. Set up mount namespace with custom resolv.conf and user bind mounts.
    namespace::setup_mount_namespace(&config.bind_mounts).context("setup_mount_namespace")?;

    // 7. Send the TUN fd to the parent.
    tracing::debug!("child: sending TUN fd to parent");
    fd_passing::send_fd(sock, tun_fd).context("send_fd")?;

    // 8. Wait for the parent's ready signal (1 byte).
    tracing::debug!("child: waiting for ready signal from parent");
    let mut ready = [0u8; 1];
    read(sock, &mut ready).context("read ready signal")?;
    tracing::debug!("child: received ready signal, launching command");

    // 9. Close setup-only fds before launching the user's command.
    let _ = close(sock);
    let _ = close(tun_fd);

    // 10. Run the command under a small reaper so forked descendants keep the
    // proxy alive after the original command process exits.
    run_command_tree(&config.command).context("run command tree")
}

/// Replace the current process with the requested command.
fn exec_command(command: &[String]) -> Result<()> {
    if command.is_empty() {
        bail!("no command specified");
    }

    let prog = CString::new(command[0].as_str()).context("CString prog")?;
    let args: Vec<CString> = command
        .iter()
        .map(|s| CString::new(s.as_str()).context("CString arg"))
        .collect::<Result<_>>()?;

    execvp(&prog, &args).context("execvp")?;
    unreachable!()
}

/// Run the requested command and wait for it plus any orphaned descendants.
fn run_command_tree(command: &[String]) -> Result<i32> {
    set_child_subreaper().context("set child subreaper")?;

    // SAFETY: still single-threaded in the namespace child; tokio only starts
    // in the outer parent process.
    let command_pid = match unsafe { fork() }.context("fork command")? {
        ForkResult::Child => {
            if let Err(e) = exec_command(command) {
                eprintln!("nsproxy: {:#}", e);
                std::process::exit(1);
            }

            unreachable!()
        }
        ForkResult::Parent { child } => child,
    };

    wait_for_command_tree(command_pid)
}

fn set_child_subreaper() -> Result<()> {
    let rc = unsafe {
        libc::prctl(
            libc::PR_SET_CHILD_SUBREAPER,
            1 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    };

    if rc == -1 {
        return Err(std::io::Error::last_os_error()).context("prctl(PR_SET_CHILD_SUBREAPER)");
    }

    Ok(())
}

fn wait_for_command_tree(command_pid: Pid) -> Result<i32> {
    let mut command_exit_code = None;

    loop {
        match waitpid(Pid::from_raw(-1), None) {
            Ok(WaitStatus::Exited(pid, code)) => {
                if pid == command_pid {
                    tracing::info!("child: command exited with code {code}");
                    command_exit_code = Some(code);
                } else {
                    tracing::debug!("child: descendant {pid} exited with code {code}");
                }
            }
            Ok(WaitStatus::Signaled(pid, sig, _)) => {
                let code = 128 + sig as i32;
                if pid == command_pid {
                    tracing::info!("child: command killed by signal {sig}");
                    command_exit_code = Some(code);
                } else {
                    tracing::debug!("child: descendant {pid} killed by signal {sig}");
                }
            }
            Ok(status) => {
                tracing::debug!("child: process status {status:?}, continuing wait");
            }
            Err(nix::errno::Errno::EINTR) => continue,
            Err(nix::errno::Errno::ECHILD) => {
                return command_exit_code
                    .ok_or_else(|| anyhow::anyhow!("command process exited without status"));
            }
            Err(e) => {
                return Err(anyhow::anyhow!("waitpid: {e}"));
            }
        }
    }
}

// ── Parent logic ─────────────────────────────────────────────────────────────

fn parent_main(sock: RawFd, child: nix::unistd::Pid, config: Config) -> Result<()> {
    // 1. Wait for child to signal that it has unshared.
    let mut unshare_signal = [0u8; 1];
    read(sock, &mut unshare_signal).context("read unshare signal from child")?;
    let needs_maps = unshare_signal[0] == 1;
    tracing::debug!("parent: child unshared, needs_maps={needs_maps}");

    // 2. If child created a user namespace, write its uid/gid maps from here.
    if needs_maps {
        let uid = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();
        namespace::write_id_maps(child.as_raw() as u32, uid, gid)
            .context("write id maps for child")?;

        // Signal child that maps are written.
        let sock_bfd = unsafe { BorrowedFd::borrow_raw(sock) };
        write(sock_bfd, &[1u8]).context("signal child maps done")?;
    }

    // 3. Receive the TUN fd from the child.
    tracing::debug!("parent: waiting for TUN fd from child");
    let tun_fd: RawFd = fd_passing::recv_fd(sock).context("recv_fd")?;
    tracing::info!("parent: received TUN fd = {tun_fd}");

    // 4. Signal child that we are ready (send byte 0x01).
    let sock_bfd = unsafe { BorrowedFd::borrow_raw(sock) };
    write(sock_bfd, &[1u8]).context("write ready signal")?;
    tracing::debug!("parent: sent ready signal to child");

    // 3. Build tokio runtime and run the event loop.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build tokio runtime")?;

    let exit_code = rt.block_on(async move {
        // Shutdown channel: event loop stops when we signal true.
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        // Spawn the event loop.
        let event_loop_handle = tokio::spawn(event_loop::run(tun_fd, config, shutdown_rx));

        // Wait for child to exit (in a blocking fashion on a separate thread).
        let child_pid = child;
        let child_wait = tokio::task::spawn_blocking(move || -> Result<i32> {
            loop {
                match waitpid(child_pid, None) {
                    Ok(WaitStatus::Exited(_, code)) => {
                        tracing::info!("parent: child exited with code {code}");
                        return Ok(code);
                    }
                    Ok(WaitStatus::Signaled(_, sig, _)) => {
                        tracing::info!("parent: child killed by signal {sig}");
                        return Ok(128 + sig as i32);
                    }
                    Ok(status) => {
                        tracing::debug!("parent: child status {status:?}, continuing wait");
                        continue;
                    }
                    Err(nix::errno::Errno::EINTR) => continue,
                    Err(e) => {
                        return Err(anyhow::anyhow!("waitpid: {e}"));
                    }
                }
            }
        });

        // Wait for child exit.
        let exit_code = match child_wait.await {
            Ok(Ok(code)) => code,
            Ok(Err(e)) => {
                tracing::warn!("child wait error: {e}");
                1
            }
            Err(e) => {
                tracing::warn!("child wait task failed: {e}");
                1
            }
        };

        // Signal the event loop to shut down.
        let _ = shutdown_tx.send(true);

        // Wait for event loop to finish (with a timeout).
        match tokio::time::timeout(std::time::Duration::from_secs(2), event_loop_handle).await {
            Ok(Ok(Ok(()))) => {
                tracing::debug!("event loop exited cleanly");
            }
            Ok(Ok(Err(e))) => {
                tracing::warn!("event loop error: {e:#}");
            }
            Ok(Err(e)) => {
                tracing::warn!("event loop task panicked: {e}");
            }
            Err(_) => {
                tracing::warn!("event loop did not exit within timeout");
            }
        }

        Ok::<i32, anyhow::Error>(exit_code)
    })?;

    // Close the TUN fd and socket.
    let _ = close(tun_fd);
    let _ = close(sock);

    std::process::exit(exit_code)
}
