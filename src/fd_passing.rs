//! File descriptor passing over a Unix socketpair using SCM_RIGHTS.
//!
//! The sender writes a single dummy byte as the iov payload so the kernel
//! accepts the ancillary message; the receiver reads it and extracts the fd
//! from the control message.

use std::io::{IoSlice, IoSliceMut};
use std::os::unix::io::RawFd;

use anyhow::{Context, Result, bail};
use nix::sys::socket::UnixAddr;
use nix::sys::socket::{ControlMessage, ControlMessageOwned, MsgFlags, recvmsg, sendmsg};

/// Send a single raw file descriptor over a connected Unix socket.
///
/// A dummy `[0u8]` byte is used as the `iov` payload; the fd travels in the
/// SCM_RIGHTS control message.
pub fn send_fd(sock: RawFd, fd: RawFd) -> Result<()> {
    let fds = [fd];
    let cmsg = [ControlMessage::ScmRights(&fds)];
    let dummy = [0u8; 1];
    let iov = [IoSlice::new(&dummy)];

    sendmsg::<UnixAddr>(sock, &iov, &cmsg, MsgFlags::empty(), None).context("sendmsg (send_fd)")?;
    Ok(())
}

/// Receive a single raw file descriptor from a connected Unix socket.
///
/// Reads and discards the dummy payload byte; returns the transferred fd.
pub fn recv_fd(sock: RawFd) -> Result<RawFd> {
    let mut buf = [0u8; 1];
    let mut iov = [IoSliceMut::new(&mut buf)];
    // cmsg_space::<T>() is a const fn in nix 0.29 — allocate a Vec<u8> of that size.
    let space = nix::sys::socket::cmsg_space::<[RawFd; 1]>();
    let mut cmsg_buf = vec![0u8; space];

    let msg = recvmsg::<UnixAddr>(sock, &mut iov, Some(&mut cmsg_buf), MsgFlags::empty())
        .context("recvmsg (recv_fd)")?;

    for cmsg in msg.cmsgs()? {
        if let ControlMessageOwned::ScmRights(fds) = cmsg
            && let Some(&fd) = fds.first()
        {
            return Ok(fd);
        }
    }

    bail!("recv_fd: no file descriptor found in ancillary data");
}
