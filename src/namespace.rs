//! Linux namespace helpers: network namespace, mount namespace, loopback, and TUN.
//!
//! Call order (in the child process after fork):
//!   1. `create_namespace()`
//!   2. `bringup_loopback()`
//!   3. `setup_mount_namespace()`
//!   4. `create_tun()` → RawFd that is passed to the parent via fd_passing

use std::collections::HashSet;
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
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

/// A validated file bind mount. Both paths are absolute and preserve their
/// directly named file or symlink object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindMount {
    pub source: PathBuf,
    pub target: PathBuf,
}

/// Parse and validate repeatable `src:dst` bind-mount specifications.
///
/// Relative paths are made absolute against `cwd` without following the final
/// symlink. Both sides must name regular files or symlinks (including dangling
/// symlinks). Duplicate and internal DNS targets are rejected before fork.
pub fn parse_bind_mounts(specs: &[String], cwd: &Path) -> Result<Vec<BindMount>> {
    if specs.is_empty() {
        return Ok(Vec::new());
    }

    let internal_targets = INTERNAL_BIND_TARGETS
        .iter()
        .map(Path::new)
        .map(std::fs::symlink_metadata)
        .map(|metadata| metadata.map(|metadata| (metadata.dev(), metadata.ino())))
        .collect::<std::io::Result<HashSet<_>>>()
        .context("inspect internal bind-mount targets")?;
    let mut targets = HashSet::new();
    let mut mounts = Vec::with_capacity(specs.len());

    for spec in specs {
        let mut fields = spec.split(':');
        let source = fields.next().unwrap_or_default();
        let target = fields.next().unwrap_or_default();
        if source.is_empty() || target.is_empty() || fields.next().is_some() {
            anyhow::bail!("invalid bind mount {spec:?}: expected exactly SRC:DST");
        }

        let (source, _) = inspect_bind_path(source, cwd, "source", spec)?;
        let (target, target_id) = inspect_bind_path(target, cwd, "target", spec)?;

        if internal_targets.contains(&target_id) {
            anyhow::bail!(
                "bind mount target {:?} conflicts with an internal DNS mount",
                target
            );
        }
        if !targets.insert(target_id) {
            anyhow::bail!("duplicate bind mount target {:?}", target);
        }

        mounts.push(BindMount { source, target });
    }

    Ok(mounts)
}

fn inspect_bind_path(
    path: &str,
    cwd: &Path,
    side: &str,
    spec: &str,
) -> Result<(PathBuf, (u64, u64))> {
    let path = Path::new(path);
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };
    let path = std::path::absolute(&path)
        .with_context(|| format!("make bind mount {side} {:?} absolute", path))?;
    let metadata = std::fs::symlink_metadata(&path)
        .with_context(|| format!("inspect bind mount {side} {:?} in {spec:?}", path))?;
    let file_type = metadata.file_type();
    if !file_type.is_file() && !file_type.is_symlink() {
        anyhow::bail!(
            "bind mount {side} {:?} in {spec:?} is not a regular file or symlink",
            path
        );
    }
    let identity = (metadata.dev(), metadata.ino());
    Ok((path, identity))
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
        bind_mount_nofollow(bind)?;
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

/// Bind-mount the directly named source object over the directly named target
/// object. The new mount API lets both pathname lookups stop at a final
/// symlink instead of following it as the classic `mount(2)` API does.
fn bind_mount_nofollow(bind: &BindMount) -> Result<()> {
    const MOVE_MOUNT_F_EMPTY_PATH: libc::c_uint = 0x0000_0004;

    let source = CString::new(bind.source.as_os_str().as_bytes())
        .with_context(|| format!("bind mount source {:?} contains a NUL byte", bind.source))?;
    let target = CString::new(bind.target.as_os_str().as_bytes())
        .with_context(|| format!("bind mount target {:?} contains a NUL byte", bind.target))?;

    let open_tree_flags =
        libc::OPEN_TREE_CLONE | libc::OPEN_TREE_CLOEXEC | libc::AT_SYMLINK_NOFOLLOW as libc::c_uint;
    // SAFETY: `source` is a valid NUL-terminated pathname. On success the
    // returned fd is uniquely owned and immediately wrapped in `OwnedFd`.
    let mount_fd = unsafe {
        libc::syscall(
            libc::SYS_open_tree,
            libc::AT_FDCWD,
            source.as_ptr(),
            open_tree_flags,
        )
    };
    if mount_fd == -1 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOSYS) {
            anyhow::bail!(
                "file bind mounts require Linux 5.2 or newer: open_tree is unavailable ({error})"
            );
        }
        return Err(error)
            .with_context(|| format!("open bind-mount source object {:?}", bind.source));
    }
    // SAFETY: a successful `open_tree` returns a new owned file descriptor.
    let mount_fd = unsafe { OwnedFd::from_raw_fd(mount_fd as RawFd) };

    // Do not pass MOVE_MOUNT_T_SYMLINKS: the target lookup must stop at the
    // directly named symlink object. The empty source path addresses the
    // detached mount object through `mount_fd`.
    // SAFETY: both path pointers are NUL-terminated and `mount_fd` is valid.
    let moved = unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            mount_fd.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_FDCWD,
            target.as_ptr(),
            MOVE_MOUNT_F_EMPTY_PATH,
        )
    };
    if moved == -1 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOSYS) {
            anyhow::bail!(
                "file bind mounts require Linux 5.2 or newer: move_mount is unavailable ({error})"
            );
        }
        return Err(error).with_context(|| {
            format!(
                "attach bind-mount source {:?} over target {:?}",
                bind.source, bind.target
            )
        });
    }

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
    use std::os::unix::fs::symlink;
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

        fn symlink(&self, target: &str, name: &str) -> PathBuf {
            let path = self.0.join(name);
            symlink(target, &path).unwrap();
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
    fn preserves_valid_and_dangling_symlink_objects() {
        let temp = TempDir::new();
        temp.file("final-source");
        temp.symlink("final-source", "second-link");
        let source = temp.symlink("second-link", "source-link");
        let target = temp.symlink("missing-target", "target-link");

        let mounts = parse_bind_mounts(&["source-link:target-link".to_owned()], &temp.0).unwrap();

        assert_eq!(mounts[0].source, source);
        assert_eq!(mounts[0].target, target);
        assert_eq!(
            fs::read_link(&mounts[0].source).unwrap(),
            Path::new("second-link")
        );
        assert!(
            fs::symlink_metadata(&mounts[0].target)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn preserves_symlink_components_in_parent_path() {
        let temp = TempDir::new();
        let real_parent = temp.0.join("real-parent");
        fs::create_dir(&real_parent).unwrap();
        fs::write(real_parent.join("source"), "source").unwrap();
        fs::write(real_parent.join("target"), "target").unwrap();
        temp.symlink("real-parent", "parent-link");

        let mounts = parse_bind_mounts(
            &["parent-link/source:parent-link/target".to_owned()],
            &temp.0,
        )
        .unwrap();

        assert_eq!(mounts[0].source, temp.0.join("parent-link/source"));
        assert_eq!(mounts[0].target, temp.0.join("parent-link/target"));
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
