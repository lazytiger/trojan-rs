use clap::{derive::IntoApp, App, AppSettings, FromArgMatches};

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
    let mut app: App = <Opts as IntoApp>::into_app();
    app.set(AppSettings::AllowExternalSubcommands);
    let mut opts = <Opts as FromArgMatches>::from_arg_matches(&app.get_matches());

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
