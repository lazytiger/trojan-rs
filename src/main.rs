use clap::{App, AppSettings, FromArgMatches};
use clap::derive::IntoApp;

use crate::config::{Mode, Opts};

mod server;
mod config;
mod proto;
mod sys;
mod proxy;
mod session;

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
