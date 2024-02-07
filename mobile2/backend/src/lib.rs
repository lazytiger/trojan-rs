use std::{
    env::join_paths,
    fs::File,
    io::{Read, Write},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, RwLock,
    },
};

use anyhow::Result;
use lazy_static::lazy_static;
use log::error;
use wry::{
    application::{
        event::{Event, StartCause, WindowEvent},
        event_loop::{ControlFlow, EventLoopWindowTarget},
        window::WindowBuilder,
    },
    webview::{WebView, WebViewBuilder},
};

use crate::{
    platform::{get_init_data, init_builder, init_logging, start_vpn, stop_vpn},
    types::{BnetConfig, Error, IPCRequest, MobileTrojanLoop, StartBnetRequest},
};

mod platform;
mod tun;
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

fn load_config() -> Result<String, Error> {
    let path = LOOPER
        .read()
        .map_err(|e| Error::Lock(e.to_string()))?
        .cache_dir
        .clone();
    let path = join_paths(&[path.as_str(), "config.json"])?;
    let mut content = String::new();
    if let Ok(mut file) = File::open(path) {
        file.read_to_string(&mut content)?;
    }
    Ok(content)
}

fn save_config() -> Result<(), Error> {
    let looper = LOOPER.read().map_err(|e| Error::Lock(e.to_string()))?;
    let path = join_paths(&[looper.cache_dir.as_str(), "config.json"])?;
    let mut file = File::options()
        .write(true)
        .truncate(true)
        .create(true)
        .open(path)?;
    let data = serde_json::to_string(&looper.config)?;
    file.write_all(data.as_bytes())?;
    Ok(())
}

fn handle_ipc(s: &String) -> Result<(), types::Error> {
    let request: IPCRequest = serde_json::from_str(s.as_str())?;
    match request.method.as_str() {
        "startInit" => {
            log::info!("start init now");
            let data = get_init_data()?;
            let response: types::InitDataResponse = serde_json::from_str(data.as_str())?;
            set_app_list(serde_json::to_string(&response.pnames)?)?;
            LOOPER
                .write()
                .map_err(|err| Error::Lock(err.to_string()))?
                .cache_dir = response.path;
            let config = load_config()?;
            set_config(config)?;
        }
        "startBnet" => {
            let payload: StartBnetRequest = serde_json::from_str(request.payload.as_str())?;
            let app = payload.config.app.clone();
            let dns = payload.config.gateway.clone();
            let gateway = payload.config.gateway.clone();
            LOOPER
                .write()
                .map_err(|err| Error::Lock(err.to_string()))?
                .config = payload.config;
            save_config()?;
            start_vpn(app, dns, gateway)?;
        }
        "stopBnet" => {
            stop_vpn()?;
        }
        _ => {
            log:error!("ipc method:{} not supported", request.method);
        }
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
        if let Err(err) = crate::platform::stop_vpn() {
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
