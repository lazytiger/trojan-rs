use std::sync::{atomic::AtomicBool, Arc, RwLock};

use anyhow::Result;
use lazy_static::lazy_static;
use wry::{
    application::{
        event::{Event, StartCause, WindowEvent},
        event_loop::{ControlFlow, EventLoop, EventLoopWindowTarget},
        window::WindowBuilder,
    },
    webview::{WebView, WebViewBuilder},
};

use crate::{
    platform::{init_builder, init_logging},
    types::{Error, IPCRequest, MobileTrojanLoop},
};

mod platform;
mod types;

lazy_static! {
    pub static ref LOOPER: RwLock<MobileTrojanLoop> = MobileTrojanLoop::new();
}
pub fn main() -> Result<()> {
    init_logging();
    let event_loop = LOOPER.write().unwrap().looper.take().unwrap();

    let mut webview = None;
    event_loop.run(move |event, event_loop, control_flow| {
        *control_flow = ControlFlow::Wait;

        match event {
            Event::NewEvents(StartCause::Init) => {
                webview = Some(build_webview(event_loop).unwrap());
            }
            Event::WindowEvent {
                event: WindowEvent::CloseRequested { .. },
                ..
            } => {
                webview.take();
                *control_flow = ControlFlow::Exit;
            }
            Event::UserEvent(code) => {
                if let Some(webview) = &webview {
                    if let Err(err) = webview.evaluate_script(&code) {
                        log::error!("run code:{} failed:{}", code, err);
                    }
                }
            }
            _ => (),
        }
    });
}

fn handle_ipc(s: &String) -> Result<(), types::Error> {
    let request: IPCRequest = serde_json::from_str(s.as_str())?;
    match request.method.as_str() {
        "startInit" => {
            log::info!("start init now");
            set_config("".to_string())?;
        }
        _ => {}
    }
    Ok(())
}

fn build_webview(event_loop: &EventLoopWindowTarget<String>) -> Result<WebView> {
    let window = WindowBuilder::new()
        .with_title("Trojan Mobile App")
        .build(event_loop)?;
    let builder = WebViewBuilder::new(window)?
        //.with_url("https://tauri.app")?
        // If you want to use custom protocol, set url like this and add files like index.html to assets directory.
        .with_url("wry://assets/index.html")?
        .with_devtools(true)
        .with_ipc_handler(|_, s| {
            if let Err(err) = handle_ipc(&s) {
                log::error!("call ipc:{} failed:{:?}", s, err);
            }
        });
    let builder = init_builder(builder);
    let webview = builder.build()?;

    Ok(webview)
}

fn call_js(code: String) -> Result<(), Error> {
    LOOPER
        .read()
        .map_err(|err| Error::Lock(err.to_string()))?
        .proxy
        .send_event(code)?;
    Ok(())
}

pub fn set_config(data: String) -> Result<(), Error> {
    call_js(format!("window.setConfig('{}');", data))
}

pub fn set_app_list(data: String) -> Result<(), Error> {
    call_js(format!("window.setAppList('{}');", data))
}

pub fn set_error(message: String) -> Result<(), Error> {
    call_js(format!("window.setError('{}');", message))
}

pub fn on_start(fd: i32) {
    let mut looper = LOOPER.write().unwrap();
    looper.running = Arc::new(AtomicBool::new(true));
    let running = looper.running.clone();
    std::thread::spawn(move || {
        if let Err(err) = std::panic::catch_unwind(|| {
            if let Err(err) = crate::tun::start_vpn(fd, running) {
                log::error!("vpn service exit with:{:?}", err);
            }
        }) {
            log::error!("vpn service exit with:{:?}", err);
        }
        if let Err(err) = stop_vpn() {
            log::error!("stop vpn failed:{:?}", err);
        }
    });
}

pub fn on_stop() {
    let looper = LOOPER.read().unwrap();
    looper.running.store(false, Ordering::Relaxed);
}

pub fn on_network_changed(enable: bool) {
    log::info!("network status changed:{}", enable);
}
