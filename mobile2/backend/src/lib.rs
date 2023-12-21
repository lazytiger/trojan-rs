mod platform;

use crate::platform::{init_builder, init_logging};
use anyhow::Result;
use wry::{
    application::{
        event::{Event, StartCause, WindowEvent},
        event_loop::{ControlFlow, EventLoop, EventLoopWindowTarget},
        window::WindowBuilder,
    },
    webview::{WebView, WebViewBuilder},
};

pub fn main() -> Result<()> {
    init_logging();
    let event_loop = EventLoop::new();

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
            _ => (),
        }
    });
}

fn handle_ipc(s: &String) -> Result<()> {
    Ok(())
}

fn build_webview(event_loop: &EventLoopWindowTarget<()>) -> Result<WebView> {
    let window = WindowBuilder::new()
        .with_title("Trojan Mobile App")
        .build(event_loop)?;
    let builder = WebViewBuilder::new(window)?
        //.with_url("https://tauri.app")?
        // If you want to use custom protocol, set url like this and add files like index.html to assets directory.
        .with_url("wry://assets/index.html")?
        .with_devtools(true)
        .with_initialization_script("console.log('hello world from init script');")
        .with_ipc_handler(|_, s| {
            if let Err(err) = handle_ipc(&s) {
                log::error!("call ipc:{} failed:{:?}", s, err);
            }
        });
    let builder = init_builder(builder);
    let webview = builder.build()?;

    Ok(webview)
}
