use clap::Clap;

use crate::config::{Mode, Opts};

mod config;
mod proto;
mod proxy;
mod resolver;
mod server;
mod sys;
mod tcp_util;
mod tls_conn;

fn main() {
    let mut opts: Opts = Opts::parse();

    config::setup_logger(&opts.log_file, opts.log_level);
    opts.setup();
    match opts.mode {
        Mode::Proxy(_) => {
            log::warn!("trojan started in proxy mode");
            proxy::run(&mut opts);
        }
        Mode::Server(_) => {
            log::warn!("trojan started in server mode");
            server::run(&mut opts);
        }
    }
}
