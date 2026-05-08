mod config;
mod event_loop;
mod fake_dns;
mod fd_passing;
mod namespace;
mod proxy;
mod tun;

use std::ffi::CString;
use std::os::unix::io::{AsRawFd, BorrowedFd, RawFd};

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
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Use HTTP CONNECT proxy (default: SOCKS5)
    #[arg(short = 'H', long = "http", conflicts_with = "socks5")]
    http: bool,

    /// Use SOCKS5 proxy (default)
    #[arg(short = 'S', long = "socks5")]
    socks5: bool,

    /// Proxy server hostname or IP
    #[arg(short = 's', long = "server", default_value = "127.0.0.1")]
    server: String,

    /// Proxy server port
    #[arg(short = 'p', long = "port", default_value_t = 1080)]
    port: u16,

    /// Proxy authentication as user:password
    #[arg(short = 'a', long = "auth")]
    auth: Option<String>,

    /// Increase verbosity (may be repeated)
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    verbose: u8,

    /// Decrease verbosity (may be repeated)
    #[arg(short = 'q', long = "quiet", action = clap::ArgAction::Count)]
    quiet: u8,

    /// Command to run inside the namespace (and its arguments)
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let cli = Cli::parse();

    // --- tracing init --------------------------------------------------------
    let verbose_level = (cli.verbose as i32) - (cli.quiet as i32);
    let log_level = match verbose_level {
        i32::MIN..=-2 => Level::ERROR,
        -1 => Level::WARN,
        0 => Level::INFO,
        1 => Level::DEBUG,
        2.. => Level::TRACE,
    };

    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .with_target(false)
        .init();

    // --- build Config --------------------------------------------------------
    let proxy_type = if cli.http {
        ProxyType::Http
    } else {
        ProxyType::Socks5
    };

    let proxy_addr: std::net::SocketAddr = format!("{}:{}", cli.server, cli.port)
        .parse()
        .with_context(|| format!("parse proxy address {}:{}", cli.server, cli.port))?;

    let proxy_auth = cli.auth.as_deref().and_then(|s| {
        let mut parts = s.splitn(2, ':');
        let user = parts.next()?.to_string();
        let pass = parts.next()?.to_string();
        Some((user, pass))
    });

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

    let parent_sock_fd: RawFd = parent_sock.as_raw_fd();
    let child_sock_fd: RawFd = child_sock.as_raw_fd();

    // --- fork ----------------------------------------------------------------
    // SAFETY: fork() is safe here — we are single-threaded at this point (no
    // tokio runtime has been started yet).
    let fork_result = unsafe { fork() }.context("fork")?;

    match fork_result {
        // ── Child ─────────────────────────────────────────────────────────
        ForkResult::Child => {
            // Drop the parent-side socket.
            drop(parent_sock);

            child_main(child_sock_fd, &config).expect("child_main failed");

            // Unreachable after execvp, but keeps the type-checker happy.
            std::process::exit(1);
        }

        // ── Parent ────────────────────────────────────────────────────────
        ForkResult::Parent { child } => {
            // Drop the child-side socket.
            drop(child_sock);

            parent_main(parent_sock_fd, child, config)?;
            Ok(())
        }
    }
}

// ── Child logic ───────────────────────────────────────────────────────────────

fn child_main(sock: RawFd, config: &Config) -> Result<()> {
    tracing::debug!("child: setting up namespace");

    // 1. Enter a new network namespace (with user-ns fallback for non-root).
    namespace::create_namespace().context("create_namespace")?;

    // 2. Bring up loopback inside the new netns.
    namespace::bringup_loopback().context("bringup_loopback")?;

    // 3. Create tun0 and configure it.
    let tun_fd: RawFd = namespace::create_tun().context("create_tun")?;

    // 4. Set up mount namespace with custom resolv.conf.
    namespace::setup_mount_namespace().context("setup_mount_namespace")?;

    // 5. Send the TUN fd to the parent.
    tracing::debug!("child: sending TUN fd to parent");
    fd_passing::send_fd(sock, tun_fd).context("send_fd")?;

    // 6. Wait for the parent's ready signal (1 byte).
    tracing::debug!("child: waiting for ready signal from parent");
    let mut ready = [0u8; 1];
    read(sock, &mut ready).context("read ready signal")?;
    if ready[0] != 1 {
        bail!("unexpected ready byte: {}", ready[0]);
    }
    tracing::debug!("child: received ready signal, exec-ing command");

    // 7. Close the socket before exec (CLOEXEC would handle it, but be explicit).
    let _ = close(sock);

    // 8. exec the user's command.
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
    tracing::debug!("parent: waiting for TUN fd from child");

    // 1. Receive the TUN fd from the child.
    let tun_fd: RawFd = fd_passing::recv_fd(sock).context("recv_fd")?;
    tracing::info!("parent: received TUN fd = {tun_fd}");

    // 2. Signal child that we are ready (send byte 0x01).
    // nix::unistd::write requires AsFd; wrap the raw fd with BorrowedFd.
    // SAFETY: sock is a valid open file descriptor owned by this scope.
    let sock_bfd = unsafe { BorrowedFd::borrow_raw(sock) };
    write(sock_bfd, &[1u8]).context("write ready signal")?;
    tracing::debug!("parent: sent ready signal to child");

    // 3. Build tokio runtime and run the event loop.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build tokio runtime")?;

    rt.block_on(async move {
        // Shutdown channel: event loop stops when we signal true.
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        // Spawn the event loop.
        let event_loop_handle = tokio::spawn(event_loop::run(tun_fd, config, shutdown_rx));

        // Wait for child to exit (in a blocking fashion on a separate thread).
        let child_pid = child;
        let child_wait = tokio::task::spawn_blocking(move || -> Result<()> {
            loop {
                match waitpid(child_pid, None) {
                    Ok(WaitStatus::Exited(_, code)) => {
                        tracing::info!("parent: child exited with code {code}");
                        return Ok(());
                    }
                    Ok(WaitStatus::Signaled(_, sig, _)) => {
                        tracing::info!("parent: child killed by signal {sig}");
                        return Ok(());
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
        if let Err(e) = child_wait.await {
            tracing::warn!("child wait task failed: {e}");
        }

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

        Ok::<(), anyhow::Error>(())
    })?;

    // Close the TUN fd and socket.
    let _ = close(tun_fd);
    let _ = close(sock);

    Ok(())
}
