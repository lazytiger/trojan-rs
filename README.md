# Trojan-rs

[![Build Status](https://github.com/lazytiger/trojan-rs/actions/workflows/rust.yml/badge.svg)](https://github.com/lazytiger/trojan-rs/actions)
[![GitHub issues](https://img.shields.io/github/issues/lazytiger/trojan-rs)](https://github.com/lazytiger/trojan-rs/issues)
[![GitHub license](https://img.shields.io/github/license/lazytiger/trojan-rs)](https://github.com/lazytiger/trojan-rs/blob/master/LICENSE)
[![Releases](https://img.shields.io/github/v/release/lazytiger/trojan-rs.svg?include_prereleases)](https://github.com/lazytiger/trojan-rs/releases)

***[Trojan](https://github.com/trojan-gfw/trojan) server and proxy programs written in Rust.***

* ***For the server mode, the protocol is compatible with [original trojan](https://github.com/trojan-gfw/trojan) except
  UDP Associate does not support domain address type (maybe later?) If
  you are not ok with that, you can use the original version, it should work
  perfectly with the proxy mode.***
* ***For the proxy mode, it uses TPROXY to relay all UDP and TCP packets, and it
  should work with the [original server](https://github.com/trojan-gfw/trojan) in both route or local type.***

## How to use it

```bash
hoping@HopingPC:~/workspace/trojan-rs$ trojan --help
trojan 0.6
Hoping White
A trojan implementation using rust

USAGE:
    trojan [OPTIONS] --local-addr <local-addr> --password <password> <SUBCOMMAND>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -a, --local-addr <local-addr>                listen address for server, format like 0.0.0.0:443
    -l, --log-file <log-file>                    log file path
    -L, --log-level <log-level>
            log level, 0 for trace, 1 for debug, 2 for info, 3 for warning, 4 for error, 5 for off [default: 2]

    -m, --marker <marker>                        set marker used by tproxy [default: 1]
    -p, --password <password>                    passwords for negotiation
    -t, --tcp-idle-timeout <tcp-idle-timeout>
            time in seconds before closing an inactive tcp connection [default: 600]

    -u, --udp-idle-timeout <udp-idle-timeout>    time in seconds before closing an inactive udp connection [default: 60]

SUBCOMMANDS:
    help      Prints this message or the help of the given subcommand(s)
    proxy     run in proxy mode
    server    run in server mode

hoping@HopingPC:~/workspace/trojan-rs$ trojan help proxy
trojan-proxy
run in proxy mode

USAGE:
    trojan proxy [OPTIONS] --hostname <hostname>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -H, --hostname <hostname>      trojan server hostname
    -P, --pool-size <pool-size>    pool size, 0 for disable [default: 0]
    -o, --port <port>              trojan server port [default: 443]

hoping@HopingPC:~/workspace/trojan-rs$ trojan help server
trojan-server
run in server mode

USAGE:
    trojan server [OPTIONS] --cert <cert> --key <key>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -n, --alpn <alpn>...                     alpn protocol supported
    -c, --cert <cert>                        certificate file path, This should contain PEM-format certificates in the
                                             right order (the first certificate should certify KEYFILE, the last should
                                             be a root CA
    -d, --dns-cache-time <dns-cache-time>    time in seconds for dns query cache [default: 300]
    -k, --key <key>                          private key file path,  This should be a RSA private key or PKCS8-encoded
                                             private key, in PEM format.
    -r, --remote-addr <remote-addr>          http backend server address [default: 127.0.0.1:80]

```

## IPTABLES settings.

A workable example as follows.
lanlist and byplist are ipsets which you can create by ipset command.

> IMPORTANT your trojan server IP should be included in byplist or lanlist, otherwise, route loop should occur.

```bash
# Add any tproxy policy rules
ip rule add fwmark 0xff table 100
ip route add local 0.0.0.0/0 dev lo table 100

# --------------- Route Rules Begin ---------------------------
# Create a new chain for router
iptables -t mangle -N TROJAN_ROUTE

# Ignore LANs and any other addresses you'd like to bypass the proxy
iptables -t mangle -A TROJAN_ROUTE -m set --match-set lanlist dst -j RETURN
iptables -t mangle -A TROJAN_ROUTE -m set --match-set byplist dst -j RETURN
iptables -t mangle -A TROJAN_ROUTE -m set --match-set chslist dst -j RETURN

# Anything else should be redirected to shadowsocks's local port
iptables -t mangle -A TROJAN_ROUTE -p tcp -j TPROXY --on-port 60080 --on-ip 127.0.0.1 --tproxy-mark 0xff
iptables -t mangle -A TROJAN_ROUTE -p udp -j TPROXY --on-port 60080 --on-ip 127.0.0.1 --tproxy-mark 0xff

# Apply the route rules
iptables -t mangle -A PREROUTING -j TROJAN_ROUTE
# ---------------- Route Rules End -----------------------------


# ---------------- Local Rules Begin --------------------------
# Create new chain for localhost
iptables -t mangle -N TROJAN_LOCAL

# Ignore Lans and any other address you'd like to bypass the proxy
iptables -t mangle -A TROJAN_LOCAL -m set --match-set lanlist dst -j RETURN
iptables -t mangle -A TROJAN_LOCAL -m set --match-set byplist dst -j RETURN
iptables -t mangle -A TROJAN_LOCAL -m set --match-set chslist dst -j RETURN

# Ignore packets sent from trojan itself.
iptables -t mangle -A TROJAN_LOCAL -m mark --mark 0xff -j RETURN

# Mark tcp 80, 443, udp 53 to reroute.
iptables -t mangle -A TROJAN_LOCAL -p udp --dport 53 -j MARK --set-xmark 0xff
iptables -t mangle -A TROJAN_LOCAL -p tcp --dport 80 -j MARK --set-xmark 0xff
iptables -t mangle -A TROJAN_LOCAL -p tcp --dport 443 -j MARK --set-xmark 0xff

# Apply the local rules
iptables -t mangle -A OUTPUT -j TROJAN_LOCAL
# ----------------- Local Rules End --------------------------------

# Flush all the rules to effect immediately
ip route flush cache
```

You can get more about iptables rules in [PRINCIPLE.md](https://github.com/lazytiger/trojan-rs/blob/master/PRINCIPLE.md)

## Windows

For Windows users, wintun mode may supply a virtual device operating on ip layer base on Wintun and Smoltcp library.  
You can check ```trojan help wintun``` for more parameter detail.

Assuming your virtual device number is 3, which can be got by ```route print```
The following command can route all traffic to 8.8.8.8 into this device.

```bash
route ADD 8.8.8.8 MASK 255.255.255.255 0.0.0.0 METRIC 1 IF 3
```

You can get more about windows global proxy
in [WINDOWS.md](https://github.com/lazytiger/trojan-rs/blob/master/WINDOWS.md)

## Special Thanks for ![Jetbrains](https://github.com/lazytiger/trojan-rs/blob/master/jetbrains.png?raw=true)

Thanks [Jetbrains](https://www.jetbrains.com/?from=trojan-rs) open source license project. Clion is a great IDE which
help me a lot when developing this project.
