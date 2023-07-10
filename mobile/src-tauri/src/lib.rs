extern crate core;

use std::{
    collections::HashSet,
    io::{BufRead, BufReader, Cursor},
    sync::{atomic::AtomicBool, Arc, RwLock},
};

use serde::{Deserialize, Serialize};
use tauri::{Manager, State, Window, Wry};

use crate::types::{EventType, VpnError};

mod types;

// Learn more about Tauri commands at https://tauri.app/v1/guides/features/command
mod platform;

#[cfg(feature = "async")]
mod atun;
#[cfg(not(feature = "async"))]
mod tun;

#[cfg(feature = "async")]
use atun::run as run_vpn;
#[cfg(not(feature = "async"))]
use tun::run as run_vpn;

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct Options {
    pub hostname: String,
    pub password: String,
    pub port: u16,
    pub mtu: usize,
    pub pool_size: usize,
    pub speed_update_ms: u128,
    pub log_level: String,
    pub dns_cache_time: u64,
    pub trusted_dns: String,
    pub untrusted_dns: String,
}

#[derive(Clone)]
pub struct Context {
    pub options: Options,
    pub blocked_domains: HashSet<String>,
}

impl Context {
    const ADDED_DOMAIN_KEY: &str = "added_domains";

    const REMED_DOMAIN_KEY: &str = "remed_domains";

    pub fn merge_domains(&mut self) -> Result<(), VpnError> {
        let added = self.load_data(Self::ADDED_DOMAIN_KEY)?;
        let mut new_added = Vec::new();
        for domain in added {
            if self.blocked_domains.insert(domain.clone()) {
                new_added.push(domain);
            }
        }
        self.save_data(Self::ADDED_DOMAIN_KEY, new_added)?;

        let removed = self.load_data(Self::REMED_DOMAIN_KEY)?;
        let mut new_removed = Vec::new();
        for domain in removed {
            if self.blocked_domains.remove(&domain) {
                new_removed.push(domain);
            }
        }
        self.save_data(Self::REMED_DOMAIN_KEY, new_removed)?;

        Ok(())
    }

    pub fn search_domain(&self, domain: String) -> Vec<String> {
        self.blocked_domains
            .iter()
            .filter_map(|key| {
                if key.contains(&domain) {
                    Some(key.clone())
                } else {
                    None
                }
            })
            .take(10)
            .collect()
    }

    fn load_data(&self, key: impl AsRef<str>) -> Result<Vec<String>, VpnError> {
        let added = platform::load_data(key)?;
        if added.is_empty() {
            Ok(Vec::new())
        } else {
            Ok(serde_json::from_str(added.as_str())?)
        }
    }

    fn save_data(&self, key: impl AsRef<str>, data: Vec<String>) -> Result<(), VpnError> {
        let data = serde_json::to_string(&data)?;
        platform::save_data(key, data)
    }

    pub fn add_domain(&mut self, domain: String) -> Result<(), VpnError> {
        if self.blocked_domains.insert(domain.clone()) {
            let mut added = self.load_data(Self::ADDED_DOMAIN_KEY)?;
            let mut removed = self.load_data(Self::REMED_DOMAIN_KEY)?;
            if let Some((index, _)) = removed.iter().enumerate().find(|(_, key)| **key == domain) {
                removed.remove(index);
                self.save_data(Self::REMED_DOMAIN_KEY, removed)?;
            } else {
                added.push(domain);
                self.save_data(Self::ADDED_DOMAIN_KEY, added)?;
            }
        }
        Ok(())
    }

    pub fn remove_domain(&mut self, domain: String) -> Result<(), VpnError> {
        if self.blocked_domains.remove(&domain) {
            let mut added = self.load_data(Self::ADDED_DOMAIN_KEY)?;
            let mut removed = self.load_data(Self::REMED_DOMAIN_KEY)?;
            if let Some((index, _)) = added.iter().enumerate().find(|(_, key)| **key == domain) {
                added.remove(index);
                self.save_data(Self::ADDED_DOMAIN_KEY, added)?;
            } else {
                removed.push(domain);
                self.save_data(Self::REMED_DOMAIN_KEY, removed)?;
            }
        }
        Ok(())
    }
}

pub type VpnState = RwLock<Context>;

#[tauri::command]
fn init_window(log_level: String, window: Window<Wry>, state: State<VpnState>) {
    if let Err(err) = WINDOW.write().map(|mut context| context.replace(window)) {
        log::error!("write lock windows failed:{}", err);
    } else {
        platform::init_log(&log_level);
        log::info!("init log with log_level:{}", log_level);
        if let Ok(mut state) = state.write() {
            if let Err(err) = state.merge_domains() {
                log::error!("merge domains failed:{:?}", err);
            }
        }
    }
}

#[tauri::command]
fn start_vpn(options: Options, window: Window<Wry>) {
    if let Ok(mut state) = window.state::<VpnState>().inner().write() {
        state.options = options;
        if let Err(err) = platform::start_vpn(state.options.mtu as i32) {
            log::error!("start_vpn failed:{:?}", err);
        }
    } else {
        log::error!("lock window state failed");
    }
}

#[tauri::command]
fn stop_vpn() {
    if let Err(err) = platform::stop_vpn() {
        log::error!("stop_vpn failed:{:?}", err);
    }
}

#[tauri::command]
fn check_self_permission(permission: String) -> bool {
    match platform::check_self_permission(permission) {
        Err(err) => {
            log::error!("check_self_permission failed:{:?}", err);
            false
        }
        Ok(ret) => ret,
    }
}

#[tauri::command]
fn request_permission(permission: String) {
    if let Err(err) = platform::request_permission(permission) {
        log::error!("request_permission failed:{:?}", err);
    }
}

#[tauri::command]
fn should_show_permission_rationale(permission: String) -> bool {
    match platform::should_show_permission_rationale(permission) {
        Err(err) => {
            log::error!("check_self_permission failed:{:?}", err);
            false
        }
        Ok(ret) => ret,
    }
}

#[tauri::command]
fn update_notification(content: String) {
    if let Err(err) = platform::update_notification(content) {
        log::error!("update notification failed:{:?}", err);
    }
}

#[tauri::command]
fn save_data(key: String, value: String) {
    if let Err(err) = platform::save_data(key, value) {
        log::error!("save data failed:{:?}", err);
    }
}

#[tauri::command]
fn load_data(key: String) -> String {
    match platform::load_data(key) {
        Err(err) => {
            log::error!("load data failed:{:?}", err);
            "".into()
        }
        Ok(ret) => ret,
    }
}

#[tauri::command]
fn search_domain(key: String, state: State<VpnState>) -> Vec<String> {
    if let Ok(state) = state.read() {
        state.search_domain(key)
    } else {
        Vec::new()
    }
}

#[tauri::command]
fn add_domain(key: String, state: State<VpnState>) {
    if let Ok(mut state) = state.write() {
        if let Err(err) = state.add_domain(key) {
            log::error!("add domain failed:{:?}", err);
        }
    }
}

#[tauri::command]
fn remove_domain(key: String, state: State<VpnState>) {
    if let Ok(mut state) = state.write() {
        if let Err(err) = state.remove_domain(key) {
            log::error!("remove domain failed:{:?}", err);
        }
    }
}

#[tauri::command]
fn start_process() {
    if let Err(err) = platform::start_vpn_process() {
        log::error!("start vpn process failed:{:?}", err);
    }
}

lazy_static::lazy_static! {
   static ref WINDOW:RwLock<Option<Window>> =RwLock::new(None);
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    std::env::set_var("RUST_BACKTRACE", "full");
    let domains = include_bytes!("../../../trojan-client/src-tauri/config/domain.txt");
    let reader = BufReader::new(Cursor::new(domains));
    let mut blocked_domains = HashSet::new();
    reader.lines().for_each(|line| {
        let _ = line.map(|line| {
            blocked_domains.insert(line);
        });
    });
    let state = RwLock::new(Context {
        options: Options::default(),
        blocked_domains,
    });
    tauri::Builder::default()
        .plugin(tauri_plugin_window::init())
        .plugin(tauri_plugin_shell::init())
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            init_window,
            start_vpn,
            stop_vpn,
            check_self_permission,
            request_permission,
            should_show_permission_rationale,
            update_notification,
            save_data,
            load_data,
            search_domain,
            add_domain,
            remove_domain,
            start_process,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

macro_rules! window {
    () => {
        WINDOW
            .read()
            .map_err(|e| types::VpnError::RLock(e.to_string()))
            .map(|window| window.clone().ok_or(types::VpnError::NoWindow))??
    };
}

pub fn emit_event<T: Serialize + Clone>(event: EventType, data: T) -> Result<(), types::VpnError> {
    let window = window!();
    window.emit(event.to_str(), data)?;
    Ok(())
}

pub fn process_vpn(fd: i32, dns: String, running: Arc<AtomicBool>) -> Result<(), types::VpnError> {
    let context = window!()
        .state::<VpnState>()
        .inner()
        .read()
        .map_err(|e| VpnError::RLock(e.to_string()))?
        .clone();
    run_vpn(fd, dns, context, running)
}

#[allow(mutable_transmutes)]
pub unsafe fn get_mut_unchecked<T>(t: &mut Arc<T>) -> &mut T {
    std::mem::transmute(t.as_ref())
}
