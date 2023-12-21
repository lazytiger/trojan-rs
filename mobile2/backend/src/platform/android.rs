use wry::webview::{WebViewBuilder, WebViewBuilderExtAndroid};

use wry::android_binding;

use crate::main;
use jni::{
    objects::{JObject, JString},
    sys::{jboolean, jint, jobject},
    AttachGuard, JNIEnv,
};
pub fn init_logging() {
    android_logger::init_once(
        android_logger::Config::default()
            .with_max_level(log::LevelFilter::Info)
            .with_tag("bnet")
            .format(|f, record| {
                write!(
                    f,
                    "[{}:{}][{}]{}",
                    record.file().unwrap_or("unknown"),
                    record.line().unwrap_or(0),
                    record.level(),
                    record.args()
                )
            }),
    );
}

fn stop_unwind<F: FnOnce() -> T, T>(f: F) -> T {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(t) => t,
        Err(err) => {
            eprintln!("attempt to unwind out of `rust` with err: {:?}", err);
            std::process::abort()
        }
    }
}

fn _start_app() {
    stop_unwind(|| main().unwrap());
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn start_app() {
    android_binding!(com_bmshi, mobiletrojan, _start_app);
}

pub fn init_builder(builder: WebViewBuilder) -> WebViewBuilder {
    builder
        .with_asset_loader("wry".into())
        .with_https_scheme(true)
}
