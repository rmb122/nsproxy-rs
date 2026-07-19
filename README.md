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
7. Published host TCP ports are accepted by the parent and connected directly
   to the namespace-side TUN address through smoltcp.


Features
--------

- Supports SOCKS5 and HTTP CONNECT proxy protocols.
- Supports proxy authentication (username/password).
- Transparent to the application -- works with statically linked binaries.
- No root privilege required (uses unprivileged user namespaces).
- No DNS leaks -- domain names are resolved by the proxy server.
- Supports publishing host TCP ports to services inside the namespace.
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
      -p, --publish <SPEC> Publish a host TCP port to the namespace (repeatable)
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
      nsproxy -x direct -p 8080:80 web-server --listen 0.0.0.0:80
      nsproxy -x direct -p 127.0.0.1:8443:443/tcp web-server --listen 0.0.0.0:443
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

For example, create a symbolic link for the US Eastern time zone and mount the
link over the existing `/etc/localtime` when running `date`:

      ln -s /usr/share/zoneinfo/America/New_York ./new-york-localtime
      nsproxy -x direct -b ./new-york-localtime:/etc/localtime date

Both paths may be relative to the directory where nsproxy is started. Each
path must name either a regular file or a symbolic link; dangling symbolic
links are allowed. Symbolic links themselves are mounted without following
their targets. A relative source link keeps its original link text, which is
then resolved relative to the destination's parent directory. Bind mounts are
read-write; directories and Docker-style mode suffixes such as `:ro` are not
supported. Duplicate targets and the internal DNS mount targets
`/etc/resolv.conf` and `/etc/nsswitch.conf` are rejected.


TCP port publishing
-------------------

Use repeatable `--publish` (`-p`) options before the command to expose TCP
services running inside the network namespace:

      [HOST_IP:]HOST_PORT:NS_PORT[/tcp]

For example:

      nsproxy -x direct -p 127.0.0.1:8080:80/tcp server --listen 0.0.0.0:80

`HOST_IP` defaults to `0.0.0.0`, which exposes the port on every host IPv4
interface. The `/tcp` suffix is optional. UDP, IPv6 addresses, random host
ports, and port ranges are not supported.

The namespace service must listen on `172.23.255.255` (the TUN address) or
`0.0.0.0`; a service bound only to namespace loopback (`127.0.0.1`) cannot be
reached. Published connections bypass proxy and routing rules. The service sees
the source as the TUN gateway `172.23.255.254`, not as the external client's
original address.


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
- Listening programs are reachable from outside only through explicitly
  published TCP ports.
- Connections to loopback addresses refer to the namespace, not the host.
- `sudo` and `su` will not work inside the namespace (only one UID is mapped).


Credits
-------

This project is a Rust reimplementation inspired by
[nsproxy](https://github.com/nlzy/nsproxy) by NaLan ZeYu. The original C
implementation uses lwIP as its user-space TCP/IP stack and forwards DNS to a
real server; this version uses smoltcp and a fake-DNS approach instead.
