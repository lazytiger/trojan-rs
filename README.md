# Trojan-rs

[![Build Status](https://travis-ci.com/lazytiger/trojan-rs.svg?branch=master)](https://travis-ci.com/lazytiger/trojan-rs)
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
trojan 0.2
Hoping White
a trojan implementation using rust

USAGE:
    trojan [OPTIONS] --local-addr <local-addr> --password <password>... <SUBCOMMAND>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -i, --idle-timeout <idle-timeout>    time in seconds before closing an inactive connection [default: 300]
    -a, --local-addr <local-addr>        listen address for server
    -l, --log-file <log-file>            log file path
    -L, --log-level <log-level>          log level, 0 for trace, 1 for debug, 2 for info, 3 for warning, 4 for error, 5
                                         for off [default: 2]
    -m, --marker <marker>                set marker used by tproxy [default: 255]
    -p, --password <password>...         passwords for negotiation

SUBCOMMANDS:
    help      Prints this message or the help of the given subcommand(s)
    proxy
    server

hoping@HopingPC:~/workspace/trojan-rs$ trojan help proxy
trojan-proxy

USAGE:
    trojan proxy --hostname <hostname>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -H, --hostname <hostname>    trojan server hostname

hoping@HopingPC:~/workspace/trojan-rs$ trojan help server
trojan-server

USAGE:
    trojan server [OPTIONS] --cert <cert> --key <key>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -c, --cert <cert>                        certificate file path
    -d, --dns-cache-time <dns-cache-time>    time in seconds for dns query cache [default: 300]
    -k, --key <key>                          private key file path
    -r, --remote-addr <remote-addr>          http backend server address [default: 127.0.0.1:80]

```

## IPTABLES settings.

A workable example as follows.
lanlist and byplist is ipset which you can create by ipset command.

> IMPORTANT your trojan server IP should be included in byplist or lanlist, otherwise, route loop should occur. 

```bash
# Add any tproxy policy rules
ip rule add fwmark 1 table 100
ip route add local 0.0.0.0/0 dev lo table 100

# --------------- Route Rules Begin ---------------------------
# Create a new chain for router
iptables -t mangle -N TROJAN_ROUTE

# Ignore LANs and any other addresses you'd like to bypass the proxy
iptables -t mangle -A TROJAN_ROUTE -m set --match-set lanlist dst -j RETURN
iptables -t mangle -A TROJAN_ROUTE -m set --match-set byplist dst -j RETURN
iptables -t mangle -A TROJAN_ROUTE -m set --match-set chslist dst -j RETURN

# Anything else should be redirected to shadowsocks's local port
iptables -t mangle -A TROJAN_ROUTE -p tcp -j TPROXY --on-port 60080 --on-ip 127.0.0.1 --tproxy-mark 1
iptables -t mangle -A TROJAN_ROUTE -p udp -j TPROXY --on-port 60080 --on-ip 127.0.0.1 --tproxy-mark 1

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
iptables -t mangle -A TROJAN_LOCAL -p udp --dport 53 -j MARK --set-xmark 1
iptables -t mangle -A TROJAN_LOCAL -p tcp --dport 80 -j MARK --set-xmark 1
iptables -t mangle -A TROJAN_LOCAL -p tcp --dport 443 -j MARK --set-xmark 1

# Apply the local rules
iptables -t mangle -A OUTPUT -j TROJAN_LOCAL
# ----------------- Local Rules End --------------------------------

# Flush all the rules to effect immediately
ip route flush cache
```

You can get more about iptables rules in [PRINCIPLE.md](https://github.com/lazytiger/trojan-rs/blob/master/PRINCIPLE.md)
