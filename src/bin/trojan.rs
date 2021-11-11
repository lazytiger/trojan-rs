use trojan::config::{Mode, Opts, OPTIONS};

fn main() {
    trojan::config::setup_logger(&OPTIONS.log_file, OPTIONS.log_level);
    let gopts: &'static Opts = unsafe { std::mem::transmute(&OPTIONS) };
    match OPTIONS.mode {
        Mode::Proxy(_) => {
            log::warn!("trojan started in proxy mode");
            trojan::proxy::run(gopts);
        }
        Mode::Server(_) => {
            log::warn!("trojan started in server mode");
            trojan::server::run(gopts);
        }
    }
}
