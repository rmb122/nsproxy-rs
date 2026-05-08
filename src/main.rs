mod config;
mod event_loop;
mod fake_dns;
mod fd_passing;
mod namespace;
mod proxy;
mod tun;

use std::ffi::CString;
use std::os::unix::io::{BorrowedFd, IntoRawFd, RawFd};

use anyhow::{Context, Result, bail};
use clap::Parser;
use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{ForkResult, close, execvp, fork, read, write};
use tracing::Level;

use config::{Config, ProxyType};

// ── CLI ───────────────────────────────────────────────────────────────────────

/// nsproxy-rs — run a command inside a dedicated network namespace whose traffic
/// is transparently proxied.
///
/// Examples:
///   nsproxy-rs curl http://example.com
///   nsproxy-rs -x socks5://127.0.0.1:1080 curl http://example.com
///   nsproxy-rs -x http://user:pass@proxy.example.com:8080 wget example.com
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Proxy URL: socks5://[user:pass@]host:port or http://[user:pass@]host:port
    #[arg(short = 'x', long = "proxy", default_value = "socks5://127.0.0.1:1080")]
    proxy: String,

    /// Increase verbosity (may be repeated)
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    verbose: u8,

    /// Suppress all log output
    #[arg(short = 'q', long = "quiet")]
    quiet: bool,

    /// Command to run inside the namespace (and its arguments)
    #[arg(trailing_var_arg = true, required = true)]
    command: Vec<String>,
}

/// Parse a proxy URL like "socks5://user:pass@host:port" into Config fields.
fn parse_proxy_url(url: &str) -> Result<(ProxyType, std::net::SocketAddr, Option<(String, String)>)> {
    // Determine scheme
    let (proxy_type, rest) = if let Some(rest) = url.strip_prefix("socks5://") {
        (ProxyType::Socks5, rest)
    } else if let Some(rest) = url.strip_prefix("socks://") {
        (ProxyType::Socks5, rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        (ProxyType::Http, rest)
    } else {
        bail!("unsupported proxy scheme in '{}'. Use socks5:// or http://", url);
    };

    // Split auth from host:port
    let (auth, host_port) = if let Some(at_pos) = rest.rfind('@') {
        let auth_str = &rest[..at_pos];
        let hp = &rest[at_pos + 1..];
        let mut parts = auth_str.splitn(2, ':');
        let user = parts.next().unwrap_or("").to_string();
        let pass = parts.next().unwrap_or("").to_string();
        if user.is_empty() {
            bail!("empty username in proxy URL");
        }
        (Some((user, pass)), hp)
    } else {
        (None, rest)
    };

    // Parse host:port
    let addr: std::net::SocketAddr = host_port
        .parse()
        .with_context(|| format!("invalid proxy address: '{}'", host_port))?;

    Ok((proxy_type, addr, auth))
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let cli = Cli::parse();

    // --- tracing init --------------------------------------------------------
    let log_level = if cli.quiet {
        None
    } else {
        Some(match cli.verbose {
            0 => Level::INFO,
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

    // Enable smoltcp's internal logging (uses `log` crate)
    let _ = env_logger::try_init();

    let verbose_level = if cli.quiet { -1 } else { cli.verbose as i32 };

    // --- build Config --------------------------------------------------------
    let (proxy_type, proxy_addr, proxy_auth) = parse_proxy_url(&cli.proxy)?;

    let config = Config {
        proxy_type,
        proxy_addr,
        proxy_auth,
        verbose: verbose_level,
        command: cli.command.clone(),
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

            if let Err(e) = child_main(child_sock_fd, &config) {
                eprintln!("nsproxy-rs: {:#}", e);
                std::process::exit(1);
            }

            // Unreachable after execvp, but keeps the type-checker happy.
            std::process::exit(1);
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

fn child_main(sock: RawFd, config: &Config) -> Result<()> {
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

    // 6. Set up mount namespace with custom resolv.conf.
    namespace::setup_mount_namespace().context("setup_mount_namespace")?;

    // 7. Send the TUN fd to the parent.
    tracing::debug!("child: sending TUN fd to parent");
    fd_passing::send_fd(sock, tun_fd).context("send_fd")?;

    // 8. Wait for the parent's ready signal (1 byte).
    tracing::debug!("child: waiting for ready signal from parent");
    let mut ready = [0u8; 1];
    read(sock, &mut ready).context("read ready signal")?;
    tracing::debug!("child: received ready signal, exec-ing command");

    // 9. Close the socket before exec.
    let _ = close(sock);

    // 10. exec the user's command.
    exec_command(&config.command)?;

    unreachable!()
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
