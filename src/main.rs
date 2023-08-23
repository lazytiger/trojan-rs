#![feature(get_mut_unchecked)]
#![feature(test)]
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::panic;

use backtrace::Backtrace;

use crate::config::{Mode, OPTIONS};

mod config;
cfg_if::cfg_if! {
    if #[cfg(windows)] {
        mod dns;
        mod wintun;
        mod awintun;
    }
}
mod aproxy;
mod aserver;
mod async_utils;
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
    #[cfg(debug_assertions)]
    #[cfg(not(target_os = "windows"))]
    unsafe {
        backtrace_on_stack_overflow::enable()
    };
    config::setup_logger(&OPTIONS.log_file, OPTIONS.log_level).unwrap();
    panic::set_hook(Box::new(|info| {
        let trace = Backtrace::new();
        let message = info.to_string();
        log::error!("application exit with error:{}\n{:?}", message, trace);
        cfg_if::cfg_if! {
          if #[cfg(windows)] {
            if let Mode::Dns(_) = OPTIONS.mode {
                dns::set_dns_server("".to_owned());
            }
            }
        }
    }));
    if let Err(err) = match OPTIONS.mode {
        Mode::Proxy(_) => {
            log::warn!(
                "trojan started in proxy mode with server:{}",
                OPTIONS.back_addr.as_ref().unwrap()
            );
            proxy::run()
        }
        Mode::Aproxy(_) => {
            log::warn!(
                "trojan started in asynchronous mode with server:{}",
                OPTIONS.back_addr.as_ref().unwrap()
            );
            aproxy::run()
        }
        Mode::Server(_) => {
            log::warn!("trojan started in synchronous server mode");
            server::run()
        }
        Mode::Aserver(_) => {
            log::warn!("trojan started in asynchronous server mode");
            aserver::run()
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
        Mode::Awintun(_) => {
            cfg_if::cfg_if! {
                if #[cfg(windows)] {
                    log::warn!("trojan started in wintun mode with server:{}", OPTIONS.back_addr.as_ref().unwrap());
                    awintun::run()
                } else {
                    panic!("trojan in wintun mode not supported on non-windows platform");
                }
            }
        }
        Mode::Dns(_) => {
            cfg_if::cfg_if! {
                if #[cfg(windows)] {
                    log::warn!("trojan started in dns mode");
                    let ret = dns::run();
                    dns::set_dns_server("".into());
                    ret
                } else {
                    panic!("trojan in dns mode not supported on non-windows platform");
                }
            }
        }
    } {
        log::error!("trojan exited with error:{:?}", err);
    }
}
