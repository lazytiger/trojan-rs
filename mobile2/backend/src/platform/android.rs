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

unsafe fn call_jni<T, R>(callback: T) -> Result<R, Error>
where
    T: FnOnce(JObject<'_>, AttachGuard<'_>) -> Result<R, Error>,
{
    let ctx = ndk_context::android_context();
    let vm = jni::JavaVM::from_raw(ctx.vm().cast())?;
    let env = vm.attach_current_thread()?;
    let ctx = JObject::from_raw(ctx.context() as jobject);
    callback(ctx, env)
}

pub fn get_init_data() -> Result<String, crate::types::Error> {
    unsafe {
        call_jni(|ctx, mut env| {
            let value = env
                .call_method(ctx, "getInitData", "()Ljava/lang/String;", &[])?
                .l()?;
            let value: jni::objects::JString = value.into();
            let value = env.get_string(&value)?.to_string_lossy().to_string();
            log::info!("init data:{}", value);
            Ok(value)
        })
    }
}

pub fn start_vpn(app: String, dns: String, gateway: String) -> Result<(), crate::types::Error> {
    unsafe {
        call_jni(|ctx, mut env| {
            let app = env.new_string(app)?;
            let dns = env.new_string(dns)?;
            let gateway = env.new_string(gateway)?;
            env.call_method(
                ctx,
                "startVpn",
                "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
                &[(&app).into(), (&dns).into(), (&gateway).into()],
            )?;
            Ok(())
        })
    }
}

pub fn stop_vpn() -> Result<(), crate::types::Error> {
    unsafe {
        call_jni(|ctx, mut env| {
            env.call_method(ctx, "stopVpn", "()V", &[])?;
            Ok(())
        })
    }
}

pub fn update_notification(message: String) -> Result<(), crate::types::Error> {
    unsafe {
        call_jni(|ctx, mut env| {
            let message = env.new_string(message)?;
            env.call_method(
                ctx,
                "updateNotification",
                "(Ljava/lang/String;)V",
                &[(&message).into()],
            )?;
            Ok(())
        })
    }
}

#[no_mangle]
pub extern "system" fn Java_com_bmshi_mobiletrojan_TrojanService_onStart<'local>(
    _: JNIEnv<'local>,
    _: JObject<'local>,
    fd: jint,
) {
    log::info!("service start with fd:{}", fd);
    if let Err(err) = set_error("serviceStarted".to_string()) {
        log::error!("call set_error failed:{:?}", err);
    }
    crate::on_start(fd);
}

#[no_mangle]
pub extern "system" fn Java_com_bmshi_mobiletrojan_TrojanService_onStop<'local>(
    _: JNIEnv<'local>,
    _: JObject<'local>,
) {
    log::info!("service stopped");
    if let Err(err) = set_error("serviceStopped".to_string()) {
        log::error!("call set_error failed:{:?}", err);
    }
    crate::on_stop();
}

#[no_mangle]
pub extern "system" fn Java_com_bmshi_mobiletrojan_TrojanService_onNetworkChanged<'local>(
    _: JNIEnv<'local>,
    _: JObject<'local>,
    available: jboolean,
) {
    log::info!("network:{}", available);
    crate::on_network_changed(available != 0)
}

#[no_mangle]
pub extern "system" fn Java_com_bmshi_mobiletrojan_MainActivity_onError<'local>(
    mut env: JNIEnv<'local>,
    _: JObject<'local>,
    message: JObject<'local>,
) {
    let message: JString<'local> = message.into();
    let message = env.get_string(&message).unwrap();
    if let Err(err) = set_error(message.to_string_lossy().to_string()) {
        log::error!("call set_error failed:{:?}", err);
    }
}
