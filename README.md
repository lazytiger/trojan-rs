# Trojan-rs
[![Build Status](https://img.shields.io/travis/lazytiger/trojan-rs)](https://travis-ci.com/lazytiger/trojan-rs)

***[Trojan](https://github.com/trojan-gfw/trojan) server and proxy programs written in Rust.***

* ***For the server mode, the protocol is compatible with [original trojan](https://github.com/trojan-gfw/trojan) except
UDP Associate does not support domain address type (maybe later?) If 
you are not ok with that, you can use the original version, it should work
perfectly with the proxy mode.***
* ***For the proxy mode, it uses TPROXY to relay all UDP and TCP packets, and it
should work with the [original server](https://github.com/trojan-gfw/trojan) in both route or local type.***

## How to use it
```bash
USAGE:
    trojan [OPTIONS] --password <password>...

FLAGS:
        --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -c, --cert <cert>                        certificate file path
    -d, --dns-cache-time <dns-cache-time>    time in seconds for dns query cache [default: 300]
    -h, --hostname <hostname>                trojan server hostname
    -i, --idle-timeout <idle-timeout>        time in seconds before closing an inactive connection [default: 300]
    -k, --key <key>                          private key file path
    -a, --local-addr <local-addr>            listen address for server [default: 0.0.0.0:443]
    -l, --log-file <log-file>                log file path
    -L, --log-level <log-level>              log level, 0 for trace, 1 for debug, 2 for info, 3 for warning, 4 for
                                             error, 5 for off [default: 2]
    -m, --marker <marker>                    set marker used by tproxy [default: 255]
    -M, --mode <mode>                        program mode, valid options are server and proxy [default: server]
    -p, --password <password>...             passwords for negotiation
    -A, --remote-addr <remote-addr>          http backend server address [default: 127.0.0.1:80]
```

For a server [-M server], the following parameters are required
* -c certificate file
* -k private key file
* -d DNS cache time
* -A backend HTTP server address

For a proxy [-M proxy], the following parameters are required
* -h trojan server address

common parameters as following:
* -i max idle time in seconds UDP connections
* -l log file path, is not specified log to console.
* -L log level
* -a listening address
* -m marker used for OUTPUT identification, you could use it in iptables
* -p password for the handshake, server mode may provide more than one
* -M mode selection

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

# Anything else should be redirected to shadowsocks's local port
iptables -t mangle -A TROJAN_ROUTE -p tcp -m set ! --match-set chslist dst -j TPROXY --on-port 60080 --on-ip 127.0.0.1 --tproxy-mark 1
iptables -t mangle -A TROJAN_ROUTE -p udp -m set ! --match-set chslist dst -j TPROXY --on-port 60080 --on-ip 127.0.0.1 --tproxy-mark 1

# Apply the route rules
iptables -t mangle -A PREROUTING -p tcp -j TROJAN_ROUTE
# ---------------- Route Rules End -----------------------------


# ---------------- Local Rules Begin --------------------------
# Create new chain for localhost
iptables -t mangle -N TROJAN_LOCAL

# Ignore Lans and any other address you'd like to bypass the proxy
iptables -t mangle -A TROJAN_LOCAL -m set --match-set lanlist dst -j RETURN
iptables -t mangle -A TROJAN_LOCAL -m set --match-set byplist dst -j RETURN

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
