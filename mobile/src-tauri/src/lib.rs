extern crate core;

use std::sync::{atomic::AtomicBool, Arc, RwLock};

use serde::{Deserialize, Serialize};
use tauri::{Manager, Window, Wry};

use crate::types::VpnError;

mod types;

// Learn more about Tauri commands at https://tauri.app/v1/guides/features/command
mod platform;

mod tun;

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct Options {
    pub hostname: String,
    pub password: String,
    pub port: u16,
    pub mtu: usize,
    pub pool_size: usize,
    pub log_level: String,
}

pub type VpnState = RwLock<Options>;

#[tauri::command]
fn init_window(log_level: String, window: Window<Wry>) {
    if let Err(err) = WINDOW.write().map(|mut context| context.replace(window)) {
        log::error!("write lock windows failed:{}", err);
    } else {
        platform::init_log(&log_level);
        log::info!("init log with log_level:{}", log_level);
    }
}

#[tauri::command]
fn start_vpn(option: Options, window: Window<Wry>) {
    if let Ok(mut state) = window.state::<VpnState>().inner().write() {
        *state = option;
        if let Err(err) = platform::start_vpn(state.mtu as i32) {
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

lazy_static::lazy_static! {
   static ref WINDOW:RwLock<Option<Window>> =RwLock::new(None);
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    //std::env::set_var("RUST_BACKTRACE", "full");
    let option = RwLock::new(Options::default());
    tauri::Builder::default()
        .plugin(tauri_plugin_window::init())
        .plugin(tauri_plugin_shell::init())
        .manage(option)
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

pub fn emit_event<T: Serialize + Clone>(event: &str, data: T) -> Result<(), types::VpnError> {
    let window = window!();
    window.emit(event, data)?;
    Ok(())
}

pub fn process_vpn(fd: i32, running: Arc<AtomicBool>) -> Result<(), types::VpnError> {
    let options = window!()
        .state::<RwLock<Options>>()
        .inner()
        .read()
        .map_err(|e| VpnError::RLock(e.to_string()))?
        .clone();
    tun::run(fd, options, running)
}

#[allow(mutable_transmutes)]
pub unsafe fn get_mut_unchecked<T>(t: &mut Arc<T>) -> &mut T {
    std::mem::transmute(t.as_ref())
}
