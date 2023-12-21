use derive_more::From;
use serde::Deserialize;
use std::{env::JoinPathsError, sync::RwLock};
use wry::application::event_loop::{EventLoop, EventLoopBuilder, EventLoopClosed, EventLoopProxy};

pub struct MobileTrojanLoop {
    pub looper: Option<EventLoop<String>>,
    pub proxy: EventLoopProxy<String>,
}

unsafe impl Sync for MobileTrojanLoop {}
unsafe impl Send for MobileTrojanLoop {}

impl MobileTrojanLoop {
    pub fn new() -> RwLock<Self> {
        let looper = EventLoopBuilder::with_user_event().build();
        let proxy = looper.create_proxy();
        RwLock::new(Self {
            looper: Some(looper),
            proxy,
        })
    }
}

#[derive(Deserialize, Default, Debug)]
pub struct IPCRequest {
    pub method: String,
    pub payload: String,
}

#[derive(From, Debug)]
pub enum Error {
    #[cfg(target_os = "android")]
    JNI(jni::errors::Error),
    JSON(serde_json::Error),
    Lock(String),
    IPC(EventLoopClosed<String>),
    Path(JoinPathsError),
    IO(std::io::Error),
}
