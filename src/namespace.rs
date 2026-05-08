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

/// Enter a new network namespace (child side).
///
/// First tries `CLONE_NEWNET` alone (requires `CAP_SYS_ADMIN`).  If that fails,
/// falls back to `CLONE_NEWUSER | CLONE_NEWNET`.
///
/// Returns `true` if a user namespace was created (parent must write uid/gid maps).
pub fn create_namespace() -> Result<bool> {
    match unshare(CloneFlags::CLONE_NEWNET) {
        Ok(()) => {
            tracing::debug!("unshare(CLONE_NEWNET) succeeded (privileged)");
            Ok(false)
        }
        Err(e) => {
            tracing::debug!("unshare(CLONE_NEWNET) failed ({e}), trying user+net namespace");
            unshare(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNET)
                .context("unshare(CLONE_NEWUSER|CLONE_NEWNET)")?;
            tracing::debug!("unshare(CLONE_NEWUSER|CLONE_NEWNET) succeeded");
            Ok(true) // parent needs to write maps
        }
    }
}

/// Write uid/gid maps for a child process from the PARENT side.
/// This avoids AppArmor restrictions on /proc/self/* writes after unshare.
pub fn write_id_maps(child_pid: u32, uid: u32, gid: u32) -> Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write;

    fn proc_write(path: &str, data: &str) -> Result<()> {
        let mut f = OpenOptions::new()
            .write(true)
            .open(path)
            .with_context(|| format!("open {}", path))?;
        f.write_all(data.as_bytes())
            .with_context(|| format!("write {}", path))?;
        Ok(())
    }

    let setgroups_path = format!("/proc/{}/setgroups", child_pid);
    let uid_map_path = format!("/proc/{}/uid_map", child_pid);
    let gid_map_path = format!("/proc/{}/gid_map", child_pid);

    // Deny setgroups (required before gid_map write)
    proc_write(&setgroups_path, "deny")?;

    // Write uid_map: "0 <real_uid> 1" — map root inside to real uid outside
    // This gives the process full capabilities inside the namespace
    proc_write(&uid_map_path, &format!("0 {} 1\n", uid))?;

    // Write gid_map: "0 <real_gid> 1"
    proc_write(&gid_map_path, &format!("0 {} 1\n", gid))?;

    tracing::debug!("wrote id maps for pid {} (uid={}, gid={})", child_pid, uid, gid);
    Ok(())
}

// ── Mount namespace + resolv.conf ────────────────────────────────────────────

/// Create a private mount namespace and bind-mount custom `resolv.conf` and
/// `nsswitch.conf` to force DNS through our fake resolver at 172.23.255.254.
pub fn setup_mount_namespace() -> Result<()> {
    unshare(CloneFlags::CLONE_NEWNS).context("unshare(CLONE_NEWNS)")?;

    // Make the mount namespace fully private (no propagation to/from host)
    nix::mount::mount(
        None::<&str>,
        "/",
        None::<&str>,
        nix::mount::MsFlags::MS_REC | nix::mount::MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .context("make root mount private")?;

    // Create temp files with random names, bind-mount them, then unlink.
    // The mount keeps the inode alive even after unlink (no leftover files).
    bind_mount_tmpfile("nameserver 172.23.255.254\n", "/etc/resolv.conf")
        .context("bind-mount resolv.conf")?;

    bind_mount_tmpfile("hosts: files dns\n", "/etc/nsswitch.conf")
        .context("bind-mount nsswitch.conf")?;

    // WORKAROUND: ssh complains about "Bad owner or permissions" on config files
    // because inside the user namespace, file owners map to nobody (65534).
    // Mount a tmpfs over ssh_config.d to hide the problematic files.
    let _ = nix::mount::mount(
        Some("tmpfs"),
        "/etc/ssh/ssh_config.d",
        Some("tmpfs"),
        nix::mount::MsFlags::empty(),
        None::<&str>,
    );

    tracing::debug!("mount namespace set up; DNS → 172.23.255.254");
    Ok(())
}

/// Create a temporary file with random name, write `content`, bind-mount over
/// `target`, then unlink the temp file (mount keeps inode alive).
fn bind_mount_tmpfile(content: &str, target: &str) -> Result<()> {
    use std::io::Write;
    use std::os::unix::io::FromRawFd;

    // nix::unistd::mkstemp creates a temp file and returns (RawFd, PathBuf)
    let (fd, path) = nix::unistd::mkstemp("/tmp/nsproxy-XXXXXX")
        .context("mkstemp")?;

    // SAFETY: mkstemp returns a valid, exclusively-owned fd
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    file.write_all(content.as_bytes())
        .with_context(|| format!("write {:?}", path))?;
    drop(file);

    // Bind-mount
    let path_str = path.to_str().context("temp path not utf8")?;
    nix::mount::mount(
        Some(path_str),
        target,
        None::<&str>,
        nix::mount::MsFlags::MS_BIND,
        None::<&str>,
    )
    .with_context(|| format!("bind-mount {:?} → {}", path, target))?;

    // Unlink — mount keeps inode alive, no leftover file on disk
    let _ = nix::unistd::unlink(&path);

    Ok(())
}

// ── Loopback ─────────────────────────────────────────────────────────────────

/// Bring up the loopback interface inside the new network namespace.
pub fn bringup_loopback() -> Result<()> {
    unsafe {
        let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if sock < 0 {
            anyhow::bail!("socket() for loopback: {}", std::io::Error::last_os_error());
        }

        let mut ifr: libc::ifreq = std::mem::zeroed();
        let name = b"lo\0";
        std::ptr::copy_nonoverlapping(name.as_ptr(), ifr.ifr_name.as_mut_ptr() as *mut u8, name.len());
        ifr.ifr_ifru.ifru_flags = (libc::IFF_UP | libc::IFF_RUNNING) as i16;

        if libc::ioctl(sock, libc::SIOCSIFFLAGS as _, &ifr as *const _) < 0 {
            let err = std::io::Error::last_os_error();
            libc::close(sock);
            if err.raw_os_error() == Some(libc::EPERM) {
                anyhow::bail!(
                    "ioctl SIOCSIFFLAGS lo: {}\n\
                     hint: If you are using Ubuntu >= 23.10, run:\n\
                     \n\
                       sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0\n\
                     \n\
                     Or add to /etc/sysctl.d/70-apparmor-userns.conf:\n\
                       kernel.apparmor_restrict_unprivileged_userns=0\n\
                     then: sudo sysctl -p /etc/sysctl.d/70-apparmor-userns.conf",
                    err
                );
            }
            anyhow::bail!("ioctl SIOCSIFFLAGS lo: {}", err);
        }
        libc::close(sock);
    }
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

    // Configure tun0 using ioctls (ip command uses RTNETLINK which may fail in user ns)
    unsafe {
        let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if sock < 0 {
            libc::close(fd);
            anyhow::bail!("socket() for tun config: {}", std::io::Error::last_os_error());
        }

        let mut ifr: libc::ifreq = std::mem::zeroed();
        let name = b"tun0\0";
        std::ptr::copy_nonoverlapping(name.as_ptr(), ifr.ifr_name.as_mut_ptr() as *mut u8, name.len());

        // Set MTU
        ifr.ifr_ifru.ifru_mtu = 65000;
        if libc::ioctl(sock, libc::SIOCSIFMTU as _, &ifr as *const _) < 0 {
            libc::close(sock); libc::close(fd);
            anyhow::bail!("ioctl SIOCSIFMTU: {}", std::io::Error::last_os_error());
        }

        // Set IP address: 172.23.255.255
        let mut addr_ifr: libc::ifreq = std::mem::zeroed();
        std::ptr::copy_nonoverlapping(name.as_ptr(), addr_ifr.ifr_name.as_mut_ptr() as *mut u8, name.len());
        let sin = &mut addr_ifr.ifr_ifru.ifru_addr as *mut libc::sockaddr as *mut libc::sockaddr_in;
        (*sin).sin_family = libc::AF_INET as u16;
        (*sin).sin_addr.s_addr = u32::from_be_bytes([172, 23, 255, 255]).to_be();
        if libc::ioctl(sock, libc::SIOCSIFADDR as _, &addr_ifr as *const _) < 0 {
            libc::close(sock); libc::close(fd);
            anyhow::bail!("ioctl SIOCSIFADDR: {}", std::io::Error::last_os_error());
        }

        // Set netmask: 255.255.255.254 (/31)
        let mut mask_ifr: libc::ifreq = std::mem::zeroed();
        std::ptr::copy_nonoverlapping(name.as_ptr(), mask_ifr.ifr_name.as_mut_ptr() as *mut u8, name.len());
        let sin = &mut mask_ifr.ifr_ifru.ifru_addr as *mut libc::sockaddr as *mut libc::sockaddr_in;
        (*sin).sin_family = libc::AF_INET as u16;
        (*sin).sin_addr.s_addr = u32::from_be_bytes([255, 255, 255, 254]).to_be();
        if libc::ioctl(sock, libc::SIOCSIFNETMASK as _, &mask_ifr as *const _) < 0 {
            libc::close(sock); libc::close(fd);
            anyhow::bail!("ioctl SIOCSIFNETMASK: {}", std::io::Error::last_os_error());
        }

        // Bring up tun0
        ifr.ifr_ifru.ifru_flags = (libc::IFF_UP | libc::IFF_RUNNING) as i16;
        if libc::ioctl(sock, libc::SIOCSIFFLAGS as _, &ifr as *const _) < 0 {
            libc::close(sock); libc::close(fd);
            anyhow::bail!("ioctl SIOCSIFFLAGS tun0 UP: {}", std::io::Error::last_os_error());
        }

        // Add default route via 172.23.255.254
        let mut route: libc::rtentry = std::mem::zeroed();
        let dst = &mut route.rt_dst as *mut libc::sockaddr as *mut libc::sockaddr_in;
        (*dst).sin_family = libc::AF_INET as u16;
        (*dst).sin_addr.s_addr = 0; // 0.0.0.0

        let gw = &mut route.rt_gateway as *mut libc::sockaddr as *mut libc::sockaddr_in;
        (*gw).sin_family = libc::AF_INET as u16;
        (*gw).sin_addr.s_addr = u32::from_be_bytes([172, 23, 255, 254]).to_be();

        let mask = &mut route.rt_genmask as *mut libc::sockaddr as *mut libc::sockaddr_in;
        (*mask).sin_family = libc::AF_INET as u16;
        (*mask).sin_addr.s_addr = 0; // 0.0.0.0

        route.rt_flags = (libc::RTF_UP | libc::RTF_GATEWAY) as u16;
        route.rt_dev = name.as_ptr() as *mut i8;

        if libc::ioctl(sock, libc::SIOCADDRT as _, &route as *const _) < 0 {
            libc::close(sock); libc::close(fd);
            anyhow::bail!("ioctl SIOCADDRT: {}", std::io::Error::last_os_error());
        }

        libc::close(sock);
    }

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
