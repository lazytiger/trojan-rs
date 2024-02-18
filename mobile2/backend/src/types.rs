use derive_more::From;
use serde::{Deserialize, Serialize};
use std::{
    env::JoinPathsError,
    sync::{atomic::AtomicBool, Arc, RwLock},
};
use wry::application::event_loop::{EventLoop, EventLoopBuilder, EventLoopClosed, EventLoopProxy};

#[derive(Default, Serialize, Deserialize, Clone)]
pub struct BnetConfig {
    pub app: String,
    pub domain: String,
    pub port: u16,
    pub password: String,
    pub gateway: String,
    pub trust_dns: String,
    pub distrust_dns: String,
    pub mtu: usize,
}

pub struct MobileTrojanLoop {
    pub looper: Option<EventLoop<String>>,
    pub proxy: EventLoopProxy<String>,
    pub running: Arc<AtomicBool>,
    pub cache_dir: String,
    pub config: BnetConfig,
}

#[derive(Deserialize)]
pub struct StartBnetRequest {
    pub config: BnetConfig,
}

unsafe impl Sync for MobileTrojanLoop {}
unsafe impl Send for MobileTrojanLoop {}

impl MobileTrojanLoop {
    pub fn new() -> RwLock<Self> {
        let looper = EventLoopBuilder::with_user_event().build();
        let proxy = looper.create_proxy();
        RwLock::new(Self {
            looper: Some(looper),
            running: Arc::new(AtomicBool::new(false)),
            cache_dir: Default::default(),
            config: Default::default(),
            proxy,
        })
    }
}

#[derive(Deserialize, Default, Debug)]
pub struct IPCRequest {
    pub method: String,
    pub payload: String,
}

#[derive(Deserialize, Debug, Default)]
pub struct InitDataResponse {
    pub path: String,
    pub pnames: Vec<String>,
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

pub type Result<T> = std::result::Result<T, Error>;
