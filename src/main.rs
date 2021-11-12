use crate::config::{Mode, OPTIONS};

mod config;
mod proto;
mod proxy;
mod resolver;
mod server;
mod sys;
mod tcp_util;
mod tls_conn;

fn main() {
    config::setup_logger(&OPTIONS.log_file, OPTIONS.log_level);
    match OPTIONS.mode {
        Mode::Proxy(_) => {
            log::warn!("trojan started in proxy mode");
            proxy::run();
        }
        Mode::Server(_) => {
            log::warn!("trojan started in server mode");
            server::run();
        }
    }
}
