//! Linux namespace helpers: network namespace, mount namespace, loopback, and TUN.
//!
//! Call order (in the child process after fork):
//!   1. `create_namespace()`
//!   2. `bringup_loopback()`
//!   3. `setup_mount_namespace()`
//!   4. `create_tun()` → RawFd that is passed to the parent via fd_passing

use std::fs;
use std::os::unix::io::RawFd;
use std::process::Command;

use anyhow::{Context, Result, bail};
use nix::sched::{CloneFlags, unshare};
use nix::unistd::{getgid, getuid};

// ── TUNSETIFF constants (architecture-aware, same logic as smoltcp) ──────────

const TUNSETIFF: libc::c_ulong = if cfg!(any(
    target_arch = "mips",
    target_arch = "mips64",
    target_arch = "powerpc",
    target_arch = "powerpc64",
    target_arch = "sparc64",
)) {
    0x800454CA
} else {
    0x400454CA
};

const IFF_TUN: libc::c_int = 0x0001;
const IFF_NO_PI: libc::c_int = 0x1000;

// ── ifreq (simplified — only the fields we need) ─────────────────────────────

#[repr(C)]
struct Ifreq {
    ifr_name: [libc::c_char; libc::IF_NAMESIZE],
    ifr_data: libc::c_int,
}

fn ifreq_for(name: &str) -> Ifreq {
    let mut ifr = Ifreq {
        ifr_name: [0; libc::IF_NAMESIZE],
        ifr_data: 0,
    };
    for (i, byte) in name.bytes().enumerate().take(libc::IF_NAMESIZE - 1) {
        ifr.ifr_name[i] = byte as libc::c_char;
    }
    ifr
}

// ── Network namespace ─────────────────────────────────────────────────────────

/// Enter a new network namespace.
///
/// First tries `CLONE_NEWNET` alone (requires `CAP_SYS_ADMIN`).  If that fails
/// (e.g. running as an unprivileged user), falls back to creating a user
/// namespace first (`CLONE_NEWUSER | CLONE_NEWNET`) and writes uid/gid maps so
/// that root inside the namespace maps to the real uid/gid outside.
pub fn create_namespace() -> Result<()> {
    match unshare(CloneFlags::CLONE_NEWNET) {
        Ok(()) => {
            tracing::debug!("unshare(CLONE_NEWNET) succeeded");
            Ok(())
        }
        Err(e) => {
            tracing::debug!("unshare(CLONE_NEWNET) failed ({e}), trying user+net namespace");
            unshare(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNET)
                .context("unshare(CLONE_NEWUSER|CLONE_NEWNET)")?;

            let uid = getuid();
            let gid = getgid();

            // Deny setgroups before writing uid_map/gid_map (kernel requirement)
            // Use OpenOptions to append (not truncate) like the original C code
            use std::fs::OpenOptions;
            use std::io::Write;

            let mut f = OpenOptions::new()
                .write(true)
                .open("/proc/self/setgroups")
                .context("open /proc/self/setgroups")?;
            f.write_all(b"deny").context("write /proc/self/setgroups")?;
            drop(f);

            // Write uid_map: "<uid> <uid> 1" (map real uid to itself)
            fs::write("/proc/self/uid_map", format!("{} {} 1\n", uid, uid))
                .context("write /proc/self/uid_map")?;

            // Write gid_map: "<gid> <gid> 1"
            fs::write("/proc/self/gid_map", format!("{} {} 1\n", gid, gid))
                .context("write /proc/self/gid_map")?;

            tracing::debug!("user+net namespace created (uid={uid}, gid={gid})");
            Ok(())
        }
    }
}

// ── Mount namespace + resolv.conf ────────────────────────────────────────────

/// Create a private mount namespace and bind-mount a custom `resolv.conf` that
/// points DNS at our virtual gateway `172.23.255.254`.
pub fn setup_mount_namespace() -> Result<()> {
    unshare(CloneFlags::CLONE_NEWNS).context("unshare(CLONE_NEWNS)")?;

    // Write a temporary resolv.conf
    let tmp_resolv = "/tmp/nsproxy-resolv.conf";
    fs::write(tmp_resolv, "nameserver 172.23.255.254\n").context("write temp resolv.conf")?;

    // Bind-mount it over /etc/resolv.conf
    nix::mount::mount(
        Some(tmp_resolv),
        "/etc/resolv.conf",
        None::<&str>,
        nix::mount::MsFlags::MS_BIND,
        None::<&str>,
    )
    .context("bind-mount resolv.conf")?;

    tracing::debug!("mount namespace set up; DNS → 172.23.255.254");
    Ok(())
}

// ── Loopback ─────────────────────────────────────────────────────────────────

/// Bring up the loopback interface inside the new network namespace.
pub fn bringup_loopback() -> Result<()> {
    run_cmd("ip", &["link", "set", "lo", "up"]).context("bring up loopback")?;
    tracing::debug!("loopback up");
    Ok(())
}

// ── TUN device ───────────────────────────────────────────────────────────────

/// Create and configure the `tun0` TUN device.
///
/// Returns the raw file descriptor of the open `/dev/net/tun` handle.
/// The caller is responsible for passing this fd to the parent process.
///
/// Configuration applied:
///   - IP:  172.23.255.255/31
///   - MTU: 65000
///   - Default route via 172.23.255.254
pub fn create_tun() -> Result<RawFd> {
    // Open /dev/net/tun
    let fd = unsafe {
        let fd = libc::open(
            b"/dev/net/tun\0".as_ptr() as *const libc::c_char,
            libc::O_RDWR,
        );
        if fd == -1 {
            return Err(std::io::Error::last_os_error()).context("open /dev/net/tun");
        }
        fd
    };

    // TUNSETIFF — request a TUN (not TAP) device, no packet info header
    let mut ifr = ifreq_for("tun0");
    ifr.ifr_data = IFF_TUN | IFF_NO_PI;

    let ret = unsafe { libc::ioctl(fd, TUNSETIFF as _, &mut ifr as *mut Ifreq) };
    if ret == -1 {
        let e = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(e).context("ioctl TUNSETIFF");
    }

    tracing::debug!("tun0 created (fd={fd})");

    // Assign IP address and bring the interface up
    run_cmd("ip", &["addr", "add", "172.23.255.255/31", "dev", "tun0"])
        .context("ip addr add tun0")?;

    run_cmd("ip", &["link", "set", "tun0", "mtu", "65000", "up"]).context("ip link set tun0 up")?;

    // Default route through the virtual gateway
    run_cmd("ip", &["route", "add", "default", "via", "172.23.255.254"])
        .context("ip route add default")?;

    tracing::debug!("tun0 configured: 172.23.255.255/31, mtu 65000, gw 172.23.255.254");
    Ok(fd)
}

// ── Internal helpers ─────────────────────────────────────────────────────────

fn run_cmd(prog: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(prog)
        .args(args)
        .status()
        .with_context(|| format!("spawn {prog}"))?;
    if !status.success() {
        bail!("{prog} {} exited with {status}", args.join(" "));
    }
    Ok(())
}
