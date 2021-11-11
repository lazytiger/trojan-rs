use crate::config::{Mode, Opts};
use clap::Parser;

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
    let gopts: &'static Opts = unsafe { std::mem::transmute(&opts) };
    match opts.mode {
        Mode::Proxy(_) => {
            log::warn!("trojan started in proxy mode");
            proxy::run(gopts);
        }
        Mode::Server(_) => {
            log::warn!("trojan started in server mode");
            server::run(gopts);
        }
    }
}
