//! Tests requiring Linux user, network, and mount namespaces and /dev/net/tun.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;

fn nsproxy(proxy: &str) -> Command {
    // Use linked DNS mount targets even when the test runner itself is inside
    // nsproxy. This fixture changes only its own private mount namespace.
    let mut command = Command::new("unshare");
    command.args([
        "-Urm", "sh", "-c",
        "mount -t tmpfs tmpfs /etc && touch /etc/resolv.conf /etc/nsswitch.conf && printf '127.0.0.1 localhost\\n' > /etc/hosts && exec \"$@\"",
        "nsproxy-test", env!("CARGO_BIN_EXE_nsproxy"),
    ]);
    command.args(["-x", proxy]);
    command
}

struct ManagedChild {
    child: Child,
    descendants: Vec<Pid>,
    output: std::sync::mpsc::Receiver<String>,
}

impl ManagedChild {
    fn spawn(script: &str) -> Self {
        Self::spawn_with_command(nsproxy("direct"), script)
    }

    fn spawn_with_command(mut command: Command, script: &str) -> Self {
        let mut child = command
            .args(["python3", "-u", "-c", script])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, output) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if tx.send(line.unwrap()).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            descendants: Vec::new(),
            output,
        }
    }

    fn read_line(&self) -> String {
        self.output
            .recv_timeout(Duration::from_secs(10))
            .expect("command must report its progress")
    }

    fn read_process_ids(&mut self) {
        let line = self.read_line();
        assert!(
            !line.is_empty(),
            "command exited before reporting its process tree"
        );
        self.descendants = line
            .split_whitespace()
            .map(|pid| Pid::from_raw(pid.parse().unwrap()))
            .collect();
    }

    fn wait(&mut self) -> std::process::ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "managed command did not terminate"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        // Clean up known fixture processes even if the regression test fails.
        for &pid in self.descendants.iter().rev() {
            let _ = kill(pid, Signal::SIGKILL);
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
#[ignore = "requires Linux namespaces and /dev/net/tun"]
fn internal_dns_mounts_are_readable_by_all_users() {
    let output = nsproxy("direct")
        .args(["sh", "-c", "stat -c '%a' /etc/resolv.conf /etc/nsswitch.conf; cat /etc/resolv.conf /etc/nsswitch.conf"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "644\n644\nnameserver 172.23.255.254\nhosts: files dns\n"
    );
}

#[test]
#[ignore = "requires Linux namespaces, /dev/net/tun, and Python 3"]
fn sigterm_terminates_and_reaps_the_entire_managed_tree() {
    let mut managed = ManagedChild::spawn(
        r#"
import os, signal, subprocess, sys, time
regular = subprocess.Popen(['sleep', '60'])
detached = subprocess.Popen(
    [sys.executable, '-u', '-c',
     'import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); print("ready"); time.sleep(60)'],
    start_new_session=True, stdout=subprocess.PIPE)
assert detached.stdout.readline() == b'ready\n'
print(os.getppid(), os.getpid(), regular.pid, detached.pid, flush=True)
time.sleep(60)
"#,
    );
    managed.read_process_ids();
    assert_eq!(managed.descendants.len(), 4);
    kill(Pid::from_raw(managed.child.id() as i32), Signal::SIGTERM).unwrap();
    assert_eq!(managed.wait().code(), Some(143));
    for pid in &managed.descendants {
        assert!(
            !std::path::Path::new(&format!("/proc/{pid}")).exists(),
            "managed process {pid} was not reaped"
        );
    }
    managed.descendants.clear();
}

fn signal_recording_command(exit_on_interrupt: bool) -> ManagedChild {
    let mut command = nsproxy("direct");
    command.env(
        "NSPROXY_TEST_EXIT_ON_INTERRUPT",
        if exit_on_interrupt { "1" } else { "0" },
    );
    let mut managed = ManagedChild::spawn_with_command(
        command,
        r#"
import os, signal, sys
received = []
def handle(signum, frame):
    name = signal.Signals(signum).name
    received.append(name)
    print(name, flush=True)
    if signum == signal.SIGINT and os.environ['NSPROXY_TEST_EXIT_ON_INTERRUPT'] == '1':
        sys.exit(0 if received == ['SIGTERM', 'SIGINT'] else 1)
signal.signal(signal.SIGTERM, handle)
signal.signal(signal.SIGINT, handle)
print(os.getppid(), os.getpid(), flush=True)
while True:
    signal.pause()
"#,
    );
    managed.read_process_ids();
    managed
}

#[test]
#[ignore = "requires Linux namespaces, /dev/net/tun, and Python 3"]
fn sigint_after_sigterm_reaches_the_command_as_sigint() {
    let mut managed = signal_recording_command(true);
    let parent = Pid::from_raw(managed.child.id() as i32);
    kill(parent, Signal::SIGTERM).unwrap();
    assert_eq!(managed.read_line(), "SIGTERM");
    kill(parent, Signal::SIGINT).unwrap();
    assert_eq!(managed.read_line(), "SIGINT");
    assert!(managed.wait().success());
    managed.descendants.clear();
}

#[test]
#[ignore = "requires Linux namespaces, /dev/net/tun, and Python 3"]
fn later_termination_signals_preserve_the_first_grace_deadline() {
    let mut managed = signal_recording_command(false);
    let parent = Pid::from_raw(managed.child.id() as i32);
    kill(parent, Signal::SIGTERM).unwrap();
    assert_eq!(managed.read_line(), "SIGTERM");
    std::thread::sleep(Duration::from_millis(1500));
    let second_signal = Instant::now();
    kill(parent, Signal::SIGINT).unwrap();
    assert_eq!(managed.read_line(), "SIGINT");
    assert_eq!(managed.wait().code(), Some(137));
    assert!(
        second_signal.elapsed() < Duration::from_millis(1500),
        "later signals must not restart the two-second grace period"
    );
    managed.descendants.clear();
}

#[test]
#[ignore = "requires Linux namespaces, /dev/net/tun, and Python 3"]
fn normal_command_exit_still_waits_for_descendants() {
    let output = nsproxy("direct").args(["python3", "-c", r#"
import subprocess, sys
subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(0.1); print("descendant finished")'])
sys.exit(7)
"#]).output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(7),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"descendant finished\n");
}

fn accept_with_timeout(listener: TcpListener) -> TcpStream {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                stream.set_nodelay(true).unwrap();
                return stream;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "proxy connection did not arrive");
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("accept: {error}"),
        }
    }
}

#[test]
#[ignore = "requires Linux namespaces, /dev/net/tun, and Python 3"]
fn http_greeting_and_subsequent_responses_reach_the_namespace() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy = format!("http://localhost:{}", listener.local_addr().unwrap().port());
    let server = std::thread::spawn(move || {
        let mut stream = accept_with_timeout(listener);
        let mut reader = BufReader::new(&mut stream);
        loop {
            let mut line = String::new();
            assert!(reader.read_line(&mut line).unwrap() > 0);
            if line == "\r\n" {
                break;
            }
        }
        stream.write_all(b"HTTP/1.1 200 OK\r\n\r\nHELLO").unwrap();
        for _ in 0..20 {
            let mut request = [0; 4];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(&request, b"PING");
            stream.write_all(b"PONG").unwrap();
        }
        let mut ack = [0; 3];
        stream.read_exact(&mut ack).unwrap();
        assert_eq!(&ack, b"ACK");
    });
    let output = nsproxy(&proxy)
        .args([
            "python3",
            "-u",
            "-c",
            r#"
import socket, statistics, time
s = socket.create_connection(('203.0.113.1', 22), timeout=5)
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
def read_exact(n):
    data = b''
    while len(data) < n:
        chunk = s.recv(n - len(data))
        assert chunk
        data += chunk
    return data
assert read_exact(5) == b'HELLO'
elapsed = []
for _ in range(20):
    start = time.perf_counter()
    s.sendall(b'PING')
    assert read_exact(4) == b'PONG'
    elapsed.append((time.perf_counter() - start) * 1000)
s.sendall(b'ACK')
print('Outbound median round trip: %.3f ms' % statistics.median(elapsed))
"#,
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    server.join().unwrap();
    println!("{}", String::from_utf8_lossy(&output.stdout).trim());
}

#[test]
#[ignore = "requires Linux namespaces, /dev/net/tun, and Python 3"]
fn published_connection_transfers_data_larger_than_forwarding_buffers() {
    let reservation = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = reservation.local_addr().unwrap();
    drop(reservation);
    let mut command = nsproxy("direct");
    command.args(["-p", &format!("127.0.0.1:{}:12345", addr.port())]);
    let mut managed = ManagedChild::spawn_with_command(
        command,
        r#"
import os, socket
listener = socket.socket()
listener.bind(('0.0.0.0', 12345))
listener.listen()
print(os.getppid(), os.getpid(), flush=True)
s, _ = listener.accept()
s.settimeout(5)
data = bytearray()
while len(data) < 1024 * 1024:
    chunk = s.recv(65536)
    assert chunk
    data.extend(chunk)
s.sendall(data)
assert s.recv(1) == b'!'
"#,
    );
    managed.read_process_ids();
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let payload: Vec<u8> = (0..1024 * 1024).map(|index| (index % 251) as u8).collect();
    stream.write_all(&payload).unwrap();
    let mut response = vec![0; payload.len()];
    stream.read_exact(&mut response).unwrap();
    assert_eq!(response, payload);
    stream.write_all(b"!").unwrap();
    assert!(managed.wait().success());
    managed.descendants.clear();
}
