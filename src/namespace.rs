//! Linux namespace helpers: network namespace, mount namespace, loopback, and TUN.
//!
//! Call order (in the child process after fork):
//!   1. `create_namespace()`
//!   2. `bringup_loopback()`
//!   3. `setup_mount_namespace()`
//!   4. `create_tun()` → RawFd that is passed to the parent via fd_passing

use std::collections::HashSet;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use nix::sched::{CloneFlags, unshare};

use crate::config::net::{DNS_ADDR, TUN_ADDR, TUN_GW, TUN_MTU, TUN_NAME, TUN_PREFIX};

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

const INTERNAL_BIND_TARGETS: [&str; 2] = ["/etc/resolv.conf", "/etc/nsswitch.conf"];

/// A validated file bind mount. Both paths are canonical absolute paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindMount {
    pub source: PathBuf,
    pub target: PathBuf,
}

/// Parse and validate repeatable `src:dst` bind-mount specifications.
///
/// Relative paths are resolved against `cwd`. Both sides must already exist
/// and resolve to regular files. Duplicate and internal DNS targets are
/// rejected before the process forks.
pub fn parse_bind_mounts(specs: &[String], cwd: &Path) -> Result<Vec<BindMount>> {
    if specs.is_empty() {
        return Ok(Vec::new());
    }

    let internal_targets = INTERNAL_BIND_TARGETS
        .iter()
        .map(Path::new)
        .map(std::fs::canonicalize)
        .collect::<std::io::Result<HashSet<_>>>()
        .context("resolve internal bind-mount targets")?;
    let mut targets = HashSet::new();
    let mut mounts = Vec::with_capacity(specs.len());

    for spec in specs {
        let mut fields = spec.split(':');
        let source = fields.next().unwrap_or_default();
        let target = fields.next().unwrap_or_default();
        if source.is_empty() || target.is_empty() || fields.next().is_some() {
            anyhow::bail!("invalid bind mount {spec:?}: expected exactly SRC:DST");
        }

        let source = canonicalize_bind_path(source, cwd, "source", spec)?;
        let target = canonicalize_bind_path(target, cwd, "target", spec)?;

        if internal_targets.contains(&target) {
            anyhow::bail!(
                "bind mount target {:?} conflicts with an internal DNS mount",
                target
            );
        }
        if !targets.insert(target.clone()) {
            anyhow::bail!("duplicate bind mount target {:?}", target);
        }

        mounts.push(BindMount { source, target });
    }

    Ok(mounts)
}

fn canonicalize_bind_path(path: &str, cwd: &Path, side: &str, spec: &str) -> Result<PathBuf> {
    let path = Path::new(path);
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };
    let path = std::fs::canonicalize(&path)
        .with_context(|| format!("resolve bind mount {side} {:?} in {spec:?}", path))?;
    let metadata = std::fs::metadata(&path)
        .with_context(|| format!("inspect bind mount {side} {:?} in {spec:?}", path))?;
    if !metadata.is_file() {
        anyhow::bail!(
            "bind mount {side} {:?} in {spec:?} is not a regular file",
            path
        );
    }
    Ok(path)
}

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

    // Write uid_map: "<uid> <uid> 1" — map real uid to itself inside namespace.
    // The initial user of a user namespace has full capabilities regardless of uid,
    // so uid 1000 still has CAP_NET_ADMIN for network configuration.
    // This keeps file ownership correct (home dir, ssh keys, etc.).
    proc_write(&uid_map_path, &format!("{} {} 1\n", uid, uid))?;

    // Write gid_map: "<gid> <gid> 1"
    proc_write(&gid_map_path, &format!("{} {} 1\n", gid, gid))?;

    tracing::debug!(
        "wrote id maps for pid {} (uid={}, gid={})",
        child_pid,
        uid,
        gid
    );
    Ok(())
}

// ── Mount namespace + resolv.conf ────────────────────────────────────────────

/// Create a private mount namespace and bind-mount custom `resolv.conf` and
/// `nsswitch.conf` to force DNS through our fake resolver.
pub fn setup_mount_namespace(bind_mounts: &[BindMount]) -> Result<()> {
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
    let resolv_conf = format!("nameserver {}\n", DNS_ADDR);
    bind_mount_tmpfile(&resolv_conf, "/etc/resolv.conf").context("bind-mount resolv.conf")?;

    bind_mount_tmpfile("hosts: files dns\n", "/etc/nsswitch.conf")
        .context("bind-mount nsswitch.conf")?;

    for bind in bind_mounts {
        nix::mount::mount(
            Some(bind.source.as_path()),
            bind.target.as_path(),
            None::<&str>,
            nix::mount::MsFlags::MS_BIND,
            None::<&str>,
        )
        .with_context(|| format!("bind-mount {:?} → {:?}", bind.source, bind.target))?;
        tracing::debug!(source = ?bind.source, target = ?bind.target, "file bind-mounted");
    }

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

    tracing::debug!("mount namespace set up; DNS → {}", DNS_ADDR);
    Ok(())
}

/// RAII guard that unlinks a path when dropped. Used to ensure temp files are
/// cleaned up on every early-return path, whether or not the bind-mount
/// succeeded. (After a successful bind-mount, unlinking the source path is
/// harmless — the kernel keeps the inode alive via the mount reference.)
struct UnlinkOnDrop(std::path::PathBuf);

impl Drop for UnlinkOnDrop {
    fn drop(&mut self) {
        let _ = nix::unistd::unlink(&self.0);
    }
}

/// Create a temporary file with random name, write `content`, bind-mount over
/// `target`, then unlink the temp file (mount keeps inode alive).
fn bind_mount_tmpfile(content: &str, target: &str) -> Result<()> {
    use std::io::Write;
    use std::os::unix::io::FromRawFd;

    // nix::unistd::mkstemp creates a temp file and returns (RawFd, PathBuf)
    let (fd, path) = nix::unistd::mkstemp("/tmp/nsproxy-XXXXXX").context("mkstemp")?;

    // Guard ensures the on-disk path is unlinked on every exit path (success,
    // write error, mount error, utf-8 error, ...). After bind_mount, the
    // inode survives because the mount itself references it.
    let _guard = UnlinkOnDrop(path.clone());

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
        std::ptr::copy_nonoverlapping(
            name.as_ptr(),
            ifr.ifr_name.as_mut_ptr() as *mut u8,
            name.len(),
        );
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

/// Compute a /prefix-length netmask as 4 big-endian octets.
///
/// E.g. `netmask_octets(31) == [255, 255, 255, 254]`.
const fn netmask_octets(prefix: u8) -> [u8; 4] {
    let mask: u32 = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix as u32)
    };
    mask.to_be_bytes()
}

/// Create and configure the TUN device inside the namespace.
///
/// Returns the raw file descriptor of the open `/dev/net/tun` handle.
/// The caller is responsible for passing this fd to the parent process.
///
/// All network parameters (name, IP, netmask, MTU, gateway) come from
/// [`crate::config::net`].
pub fn create_tun() -> Result<RawFd> {
    // Null-terminated, libc-compatible interface name.
    // IF_NAMESIZE includes the terminating NUL, so the name itself is
    // bounded by IF_NAMESIZE - 1 bytes. Linux's maximum is 15 chars.
    if TUN_NAME.len() >= libc::IF_NAMESIZE {
        anyhow::bail!(
            "configured TUN_NAME {:?} exceeds IF_NAMESIZE ({})",
            TUN_NAME,
            libc::IF_NAMESIZE
        );
    }
    let mut name_buf = [0u8; libc::IF_NAMESIZE];
    name_buf[..TUN_NAME.len()].copy_from_slice(TUN_NAME.as_bytes());
    // Trailing NUL already in place from zero-init.

    // Open /dev/net/tun
    let fd = unsafe {
        let fd = libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR);
        if fd == -1 {
            return Err(std::io::Error::last_os_error()).context("open /dev/net/tun");
        }
        fd
    };

    // TUNSETIFF — request a TUN (not TAP) device, no packet info header
    let mut ifr = ifreq_for(TUN_NAME);
    ifr.ifr_data = IFF_TUN | IFF_NO_PI;

    let ret = unsafe { libc::ioctl(fd, TUNSETIFF as _, &mut ifr as *mut Ifreq) };
    if ret == -1 {
        let e = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(e).context("ioctl TUNSETIFF");
    }

    tracing::debug!("{} created (fd={fd})", TUN_NAME);

    // Configure the TUN interface via ioctls. The `ip` command uses RTNETLINK
    // which may fail inside a user namespace.
    unsafe {
        let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if sock < 0 {
            libc::close(fd);
            anyhow::bail!(
                "socket() for tun config: {}",
                std::io::Error::last_os_error()
            );
        }

        let mut ifr: libc::ifreq = std::mem::zeroed();
        std::ptr::copy_nonoverlapping(
            name_buf.as_ptr(),
            ifr.ifr_name.as_mut_ptr() as *mut u8,
            name_buf.len(),
        );

        // Set MTU
        ifr.ifr_ifru.ifru_mtu = TUN_MTU as libc::c_int;
        if libc::ioctl(sock, libc::SIOCSIFMTU as _, &ifr as *const _) < 0 {
            libc::close(sock);
            libc::close(fd);
            anyhow::bail!("ioctl SIOCSIFMTU: {}", std::io::Error::last_os_error());
        }

        // Set IP address
        let mut addr_ifr: libc::ifreq = std::mem::zeroed();
        std::ptr::copy_nonoverlapping(
            name_buf.as_ptr(),
            addr_ifr.ifr_name.as_mut_ptr() as *mut u8,
            name_buf.len(),
        );
        let sin = &mut addr_ifr.ifr_ifru.ifru_addr as *mut libc::sockaddr as *mut libc::sockaddr_in;
        (*sin).sin_family = libc::AF_INET as u16;
        (*sin).sin_addr.s_addr = u32::from_be_bytes(TUN_ADDR.octets()).to_be();
        if libc::ioctl(sock, libc::SIOCSIFADDR as _, &addr_ifr as *const _) < 0 {
            libc::close(sock);
            libc::close(fd);
            anyhow::bail!("ioctl SIOCSIFADDR: {}", std::io::Error::last_os_error());
        }

        // Set netmask (computed from TUN_PREFIX)
        let mut mask_ifr: libc::ifreq = std::mem::zeroed();
        std::ptr::copy_nonoverlapping(
            name_buf.as_ptr(),
            mask_ifr.ifr_name.as_mut_ptr() as *mut u8,
            name_buf.len(),
        );
        let sin = &mut mask_ifr.ifr_ifru.ifru_addr as *mut libc::sockaddr as *mut libc::sockaddr_in;
        (*sin).sin_family = libc::AF_INET as u16;
        (*sin).sin_addr.s_addr = u32::from_be_bytes(netmask_octets(TUN_PREFIX)).to_be();
        if libc::ioctl(sock, libc::SIOCSIFNETMASK as _, &mask_ifr as *const _) < 0 {
            libc::close(sock);
            libc::close(fd);
            anyhow::bail!("ioctl SIOCSIFNETMASK: {}", std::io::Error::last_os_error());
        }

        // Bring up the interface
        ifr.ifr_ifru.ifru_flags = (libc::IFF_UP | libc::IFF_RUNNING) as i16;
        if libc::ioctl(sock, libc::SIOCSIFFLAGS as _, &ifr as *const _) < 0 {
            libc::close(sock);
            libc::close(fd);
            anyhow::bail!(
                "ioctl SIOCSIFFLAGS {} UP: {}",
                TUN_NAME,
                std::io::Error::last_os_error()
            );
        }

        // Add default route via TUN_GW
        let mut route: libc::rtentry = std::mem::zeroed();
        let dst = &mut route.rt_dst as *mut libc::sockaddr as *mut libc::sockaddr_in;
        (*dst).sin_family = libc::AF_INET as u16;
        (*dst).sin_addr.s_addr = 0; // 0.0.0.0

        let gw = &mut route.rt_gateway as *mut libc::sockaddr as *mut libc::sockaddr_in;
        (*gw).sin_family = libc::AF_INET as u16;
        (*gw).sin_addr.s_addr = u32::from_be_bytes(TUN_GW.octets()).to_be();

        let mask = &mut route.rt_genmask as *mut libc::sockaddr as *mut libc::sockaddr_in;
        (*mask).sin_family = libc::AF_INET as u16;
        (*mask).sin_addr.s_addr = 0; // 0.0.0.0

        route.rt_flags = libc::RTF_UP | libc::RTF_GATEWAY;
        route.rt_dev = name_buf.as_ptr() as *mut libc::c_char;

        if libc::ioctl(sock, libc::SIOCADDRT as _, &route as *const _) < 0 {
            libc::close(sock);
            libc::close(fd);
            anyhow::bail!("ioctl SIOCADDRT: {}", std::io::Error::last_os_error());
        }

        libc::close(sock);
    }

    tracing::debug!(
        "{} configured: {}/{}, mtu {}, gw {}",
        TUN_NAME,
        TUN_ADDR,
        TUN_PREFIX,
        TUN_MTU,
        TUN_GW
    );
    Ok(fd)
}

#[cfg(test)]
mod bind_mount_tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static NEXT_TEMP_DIR: AtomicU64 = AtomicU64::new(0);

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let id = NEXT_TEMP_DIR.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "nsproxy-bind-test-{}-{nanos}-{id}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn file(&self, name: &str) -> PathBuf {
            let path = self.0.join(name);
            fs::write(&path, name).unwrap();
            path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn parses_absolute_and_relative_file_paths() {
        let temp = TempDir::new();
        let source = temp.file("source");
        let target = temp.file("target");
        let absolute = format!("{}:{}", source.display(), target.display());

        let absolute_mounts = parse_bind_mounts(&[absolute], &temp.0).unwrap();
        let relative_mounts = parse_bind_mounts(&["source:target".to_owned()], &temp.0).unwrap();

        assert_eq!(absolute_mounts, relative_mounts);
        assert!(absolute_mounts[0].source.is_absolute());
        assert!(absolute_mounts[0].target.is_absolute());
    }

    #[test]
    fn rejects_invalid_bind_syntax() {
        let cwd = std::env::current_dir().unwrap();
        for spec in ["source", ":target", "source:", "a:b:c"] {
            assert!(parse_bind_mounts(&[spec.to_owned()], &cwd).is_err());
        }
    }

    #[test]
    fn rejects_missing_paths_and_directories() {
        let temp = TempDir::new();
        let source = temp.file("source");
        let target = temp.file("target");

        assert!(parse_bind_mounts(&["missing:target".to_owned()], &temp.0).is_err());
        assert!(parse_bind_mounts(&["source:missing".to_owned()], &temp.0).is_err());
        assert!(
            parse_bind_mounts(
                &[format!("{}:{}", temp.0.display(), target.display())],
                &temp.0
            )
            .is_err()
        );
        assert!(
            parse_bind_mounts(
                &[format!("{}:{}", source.display(), temp.0.display())],
                &temp.0
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_duplicate_and_internal_targets() {
        let temp = TempDir::new();
        temp.file("source-one");
        temp.file("source-two");
        temp.file("target");
        let duplicates = vec![
            "source-one:target".to_owned(),
            "source-two:./target".to_owned(),
        ];

        assert!(parse_bind_mounts(&duplicates, &temp.0).is_err());

        let internal = "source-one:/etc/resolv.conf".to_owned();
        assert!(parse_bind_mounts(&[internal], &temp.0).is_err());
    }
}
