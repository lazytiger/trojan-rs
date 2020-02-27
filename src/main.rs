use clap::Clap;

use crate::config::Opts;

mod server;
mod config;
mod proto;
mod sys;
mod proxy;
mod session;

fn main() {
    let mut opts = Opts::parse();
    config::setup_logger(&opts.log_file, opts.log_level);
    opts.setup();
    if opts.mode == "server" {
        log::warn!("trojan started in server mode");
        server::run(&mut opts);
    } else {
        log::warn!("trojan started in proxy mode");
        proxy::run(&mut opts);
    }
}
