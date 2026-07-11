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
      -x, --proxy <PROXY>  Default route
      -r, --rule <RULE>    Routing rule (repeatable); see "Routing rules" below
      -b, --bind <SRC:DST> Bind-mount a file in the namespace (repeatable)
      -v, --verbose        Enable log output; repeat for trace-level logs
      -h, --help           Print help

    Proxy format:
      direct
      socks5://[user:pass@]host:port
      http://[user:pass@]host:port

    Examples:
      nsproxy -x socks5://127.0.0.1:1080 curl http://example.com
      nsproxy -x socks5://127.0.0.1:1080 curl http://example.com
      nsproxy -x http://user:pass@proxy:8080 wget http://example.com
      nsproxy -x direct -r domain:example.com=socks5://127.0.0.1:1080 curl http://example.com
      nsproxy -x direct -b ./custom.conf:/etc/example.conf cat /etc/example.conf
      nsproxy -x socks5://127.0.0.1:1080 ssh user@remote-host
      nsproxy -x socks5://127.0.0.1:1080 -r cidr:10.0.0.0/8=direct curl http://internal


Routing rules
-------------

Connections that match a `--rule` (`-r`) rule use the route on the right side
instead of the default selected by `-x`. The flag is repeatable, and both a
match and a route are required:

      ip:<address>=<proxy>
      cidr:<network>/<prefix>=<proxy>
      domain:<host>=<proxy>
      domain-regex:<regex>=<proxy>

For example:

      -r ip:1.1.1.1=socks5://127.0.0.1:1081
      -r cidr:10.0.0.0/8=direct
      -r domain:example.com=http://127.0.0.1:8080

IP and CIDR rules use longest-prefix matching; the first rule wins when two
matching prefixes have the same length. Domain and domain-regex rules use the
first matching rule in command-line order.

Notes:

- `ip` / `cidr` rules match the destination IP. They take effect when the
  application connects to a numeric address (no DNS lookup involved).
- `domain` / `domain-regex` rules match the host name extracted from the
  intercepted DNS query. Matching is case-insensitive for `domain`.
- A `direct` domain route uses the host's resolver, so it opts in to host-side
  DNS resolution for that domain.


File bind mounts
----------------

Use repeatable `--bind` (`-b`) options before the command to expose custom
files inside the command's mount namespace:

      nsproxy -x direct -b ./config.toml:/etc/myapp/config.toml myapp

For example, run `date` with the US Eastern time zone by mounting its zoneinfo
file over the existing `/etc/localtime`:

      nsproxy -x direct -b /usr/share/zoneinfo/America/New_York:/etc/localtime date

Both paths may be relative to the directory where nsproxy is started. Each
path must name either a regular file or a symbolic link; dangling symbolic
links are allowed. Symbolic links themselves are mounted without following
their targets. A relative source link keeps its original link text, which is
then resolved relative to the destination's parent directory. Bind mounts are
read-write; directories and Docker-style mode suffixes such as `:ro` are not
supported. Duplicate targets and the internal DNS mount targets
`/etc/resolv.conf` and `/etc/nsswitch.conf` are rejected.


Requirements
------------

- Linux kernel with user namespace support.
- File bind mounts (`-b` / `--bind`) require Linux >= 5.2. Other features do
  not use this newer mount API.
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
