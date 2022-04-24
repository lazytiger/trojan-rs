#![feature(ip)]
#![feature(get_mut_unchecked)]
#![feature(test)]

extern crate core;

use crate::config::{Mode, OPTIONS};

mod config;
cfg_if::cfg_if! {
    if #[cfg(windows)] {
        mod dns;
        mod wintun;
    }
}
mod idle_pool;
mod proto;
mod proxy;
mod resolver;
mod server;
mod status;
mod sys;
mod tcp_util;
mod tls_conn;
mod types;
mod utils;

fn main() {
    config::setup_logger(&OPTIONS.log_file, OPTIONS.log_level);
    if let Err(err) = match OPTIONS.mode {
        Mode::Proxy(_) => {
            log::warn!(
                "trojan started in dns mode with server:{}",
                OPTIONS.back_addr.as_ref().unwrap()
            );
            proxy::run()
        }
        Mode::Server(_) => {
            log::warn!("trojan started in server mode");
            server::run()
        }
        Mode::Wintun(_) => {
            cfg_if::cfg_if! {
                if #[cfg(windows)] {
                    log::warn!("trojan started in wintun mode with server:{}", OPTIONS.back_addr.as_ref().unwrap());
                    wintun::run()
                } else {
                    panic!("trojan in wintun mode not supported on non-windows platform");
                }
            }
        }
        Mode::Dns(_) => {
            cfg_if::cfg_if! {
                if #[cfg(windows)] {
                    log::warn!("trojan started in dns mode");
                    dns::run()
                } else {
                    panic!("trojan in dns mode not supported on non-windows platform");
                }
            }
        }
    } {
        log::error!("trojan exited with error:{:?}", err);
    }
}
