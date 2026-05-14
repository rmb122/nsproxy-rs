nsproxy-rs
==========

nsproxy-rs is a Linux command-line tool that forces applications to use a
specified SOCKS5 or HTTP proxy, using network namespaces for transparent
traffic interception.

It creates a TUN device inside an isolated network namespace, runs the target
application there, and forwards all TCP traffic through the configured proxy
server. DNS queries are intercepted locally using a fake-IP scheme (similar to
proxychains-ng), which prevents DNS leaks by sending domain names directly to
the proxy for remote resolution.


How it works
------------

1. Fork a child process into a new network namespace (with user namespace
   fallback for unprivileged users).
2. Configure a TUN device as the sole network interface inside the namespace.
3. The parent process reads raw IP packets from the TUN device and processes
   them through a user-space TCP/IP stack (smoltcp).
4. DNS queries (UDP port 53) are intercepted and answered with fake IPs from
   the 198.18.0.0/15 pool. A bidirectional mapping between domain names and
   fake IPs is maintained.
5. When the application connects to a fake IP, the original domain name is
   recovered from the mapping and a CONNECT request is sent to the proxy
   using the domain name (ATYP=DOMAIN for SOCKS5, Host header for HTTP).
6. Data is shuttled bidirectionally between the smoltcp TCP socket and the
   upstream proxy connection.


Features
--------

- Supports SOCKS5 and HTTP CONNECT proxy protocols.
- Supports proxy authentication (username/password).
- Transparent to the application -- works with statically linked binaries.
- No root privilege required (uses unprivileged user namespaces).
- No DNS leaks -- domain names are resolved by the proxy server.
- Does not affect other processes on the system.


Build
-----

    cargo build --release

The binary will be at `target/release/nsproxy`.


Usage
-----

    nsproxy [OPTIONS] <COMMAND>...

    Options:
      -x, --proxy <URL>   Proxy URL (default: socks5://127.0.0.1:1080)
      -v, --verbose       Increase verbosity (repeatable)
      -q, --quiet         Suppress all log output
      -h, --help          Print help

    Proxy URL format:
      socks5://[user:pass@]host:port
      http://[user:pass@]host:port

    Examples:
      nsproxy curl http://example.com
      nsproxy -x socks5://127.0.0.1:1080 curl http://example.com
      nsproxy -x http://user:pass@proxy:8080 wget http://example.com
      nsproxy -q ssh user@remote-host


Requirements
------------

- Linux kernel with user namespace support.
- On Ubuntu >= 23.10, you may need to disable the AppArmor restriction:

      sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0


Limitations
-----------

- TCP only (UDP forwarding is not implemented).
- IPv4 only.
- Programs that listen on ports (servers) will not be reachable from outside.
- Connections to loopback addresses refer to the namespace, not the host.
- `sudo` and `su` will not work inside the namespace (only one UID is mapped).


Credits
-------

This project is a Rust reimplementation inspired by
[nsproxy](https://github.com/nlzy/nsproxy) by NaLan ZeYu. The original C
implementation uses lwIP as its user-space TCP/IP stack and forwards DNS to a
real server; this version uses smoltcp and a fake-DNS approach instead.
