#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, SystemTime},
};

use backtrace::Backtrace;
use derive_more::From;
use log::LevelFilter;
use serde::{Deserialize, Serialize};
use tauri::{
    api::process::{Command, CommandChild, CommandEvent},
    CustomMenuItem, Icon, Manager, RunEvent, State, SystemTray, SystemTrayEvent, SystemTrayMenu,
    SystemTrayMenuItem, Window, WindowEvent, Wry,
};
use tauri_plugin_log::LogTarget;

use wintool::adapter::{get_dns_server, get_main_adapter_ip};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(From, Debug)]
pub enum Error {
    StdIo(std::io::Error),
    SerdeJson(serde_json::Error),
    SystemTime(std::time::SystemTimeError),
    #[from(ignore)]
    Custom(String),
}

#[derive(Deserialize, Serialize, Debug, Default, Clone)]
pub struct Config {
    pub iface_name: String,
    pub server_domain: String,
    pub server_auth: String,
    pub log_level: String,
    pub pool_size: u32,
    pub enable_ipset: bool,
    pub inverse_route: bool,
    pub enable_dns: bool,
    pub sync_mode: bool,
    pub dns_listen: String,
    pub trust_dns: String,
}

impl Config {
    fn log_level_str(&self) -> &'static str {
        match self.log_level.as_str() {
            "Trace" => "0",
            "Debug" => "1",
            "Info" => "2",
            "Warn" => "3",
            "Error" => "4",
            _ => "5",
        }
    }
}

pub struct TrojanProxy {
    config: Config,
    wintun: Option<CommandChild>,
    dns: Option<CommandChild>,
    running_icon: Icon,
    stopped_icon: Icon,
    rx_speed: f32,
    tx_speed: f32,
    last_update: SystemTime,
    default_dns: String,
    explicit_dns: bool,
}

impl TrojanProxy {
    fn new() -> TrojanProxy {
        TrojanProxy {
            config: init_config().unwrap_or_default(),
            wintun: None,
            dns: None,
            running_icon: Icon::Raw(include_bytes!("../icons/icon.ico").to_vec()),
            stopped_icon: Icon::Raw(include_bytes!("../icons/icon_gray.png").to_vec()),
            rx_speed: 0.0,
            tx_speed: 0.0,
            last_update: SystemTime::UNIX_EPOCH,
            default_dns: String::new(),
            explicit_dns: false,
        }
    }

    fn update_dns(&mut self) -> Result<()> {
        let ret = get_dns_server();
        if ret.is_none() {
            return Err(Error::Custom("dns server not found".to_string()));
        }
        let (dns, set) = ret.unwrap();
        let addr = get_main_adapter_ip();
        if addr.is_none() {
            return Err(Error::Custom("main adapter ip not found".to_string()));
        }
        let addr = addr.unwrap();
        if addr == dns || dns == "127.0.0.1" {
            wintool::adapter::set_dns_server("".to_string());
            return Err(Error::Custom("invalid dns, auto dns enable".to_string()));
        }
        log::info!("dns server:{} explicit:{}", dns, set);
        self.default_dns = dns;
        self.explicit_dns = set;
        Ok(())
    }

    fn get_speed(&mut self) -> Result<(f32, f32)> {
        let metadata = std::fs::metadata("logs\\wintun.status")?;
        let mod_time = metadata.modified()?;
        if mod_time > self.last_update {
            let mut file = File::open("logs\\wintun.status")?;
            let mut content = String::new();
            let _ = file.read_to_string(&mut content)?;
            let mut split = content.split(' ');
            self.rx_speed = split
                .next()
                .map(|s| s.parse().unwrap_or_default())
                .unwrap_or_default();
            self.tx_speed = split
                .next()
                .map(|s| s.parse().unwrap_or_default())
                .unwrap_or_default();
            self.last_update = mod_time;
        } else if self.last_update.elapsed()?.as_secs() > 1 {
            self.rx_speed = 0.0;
            self.tx_speed = 0.0;
        }
        Ok((self.rx_speed, self.tx_speed))
    }
}

type TrojanState = Arc<Mutex<TrojanProxy>>;

#[tauri::command]
fn start(config: Config, state: State<TrojanState>, window: Window<Wry>) {
    log::info!("start trojan now");
    if let Err(err) = save_config(&config) {
        log::error!("save config failed:{:?}", err);
    } else {
        state.lock().unwrap().config = config;
        if let Err(err) = state.lock().unwrap().update_dns() {
            log::error!("update_dns failed:{:?}", err);
            return;
        }

        emit_state_update_event(true, window.clone());

        if state.lock().unwrap().wintun.is_some() {
            return;
        }
        let state = state.inner().clone();
        tauri::async_runtime::spawn(async move {
            let config = state.lock().unwrap().config.clone();
            let default_dns = state.lock().unwrap().default_dns.clone() + ":53";
            let pool_size = config.pool_size.to_string();
            let config_ipset = window
                .app_handle()
                .path_resolver()
                .resolve_resource("config/ipset.txt")
                .unwrap();
            let config_wintun = window
                .app_handle()
                .path_resolver()
                .resolve_resource("libs/wintun.dll")
                .unwrap();
            let command = if config.sync_mode {
                "wintun"
            } else {
                "awintun"
            };
            let mut args = vec![
                "-l",
                "logs\\wintun.log",
                "-L",
                config.log_level_str(),
                "-a",
                "127.0.0.1:60080",
                "-p",
                config.server_auth.as_str(),
                command,
                "-n",
                config.iface_name.as_str(),
                "-H",
                config.server_domain.as_str(),
                "-s",
                "logs\\wintun.status",
                "--dns-server-addr",
                default_dns.as_str(),
                "-P",
                pool_size.as_str(),
                "-w",
                config_wintun.to_str().unwrap(),
            ];
            if config.enable_ipset {
                args.push("--route-ipset");
                args.push(config_ipset.to_str().unwrap());
                if config.inverse_route {
                    args.push("--inverse-route");
                }
            }
            log::info!("{:?}", args);
            let mut rxs = HashMap::new();
            match Command::new_sidecar("trojan").unwrap().args(args).spawn() {
                Ok((rx, child)) => {
                    state.lock().unwrap().wintun.replace(child);
                    rxs.insert("wintun", rx);
                }
                Err(err) => {
                    log::error!("start wintun failed:{:?}", err);
                    emit_state_update_event(false, window);
                    return;
                }
            };
            if state.lock().unwrap().config.enable_dns {
                tokio::time::sleep(Duration::from_secs(10)).await;
                let dns_listen = config.dns_listen.clone() + ":53";
                let default_dns = state.lock().unwrap().default_dns.clone();
                let config_domains = window
                    .app_handle()
                    .path_resolver()
                    .resolve_resource("config/domain.txt")
                    .unwrap();
                let config_hosts = window
                    .app_handle()
                    .path_resolver()
                    .resolve_resource("config/hosts.txt")
                    .unwrap();
                let mut args = vec![
                    "-l",
                    "logs\\dns.log",
                    "-L",
                    config.log_level_str(),
                    "-a",
                    "127.0.0.1:60080",
                    "-p",
                    config.server_auth.as_str(),
                    "dns",
                    "-n",
                    config.iface_name.as_str(),
                    "--blocked-domain-list",
                    config_domains.to_str().unwrap(),
                    "--poisoned-dns",
                    default_dns.as_str(),
                    "--trusted-dns",
                    config.trust_dns.as_str(),
                    "--dns-listen-address",
                    dns_listen.as_str(),
                    "--hosts",
                    config_hosts.to_str().unwrap(),
                ];
                if !config.enable_ipset {
                    args.push("--add-route");
                }
                log::info!("{:?}", args);
                match Command::new_sidecar("trojan").unwrap().args(args).spawn() {
                    Ok((rx, child)) => {
                        state.lock().unwrap().dns.replace(child);
                        rxs.insert("dns", rx);
                    }
                    Err(err) => {
                        log::error!("start dns failed:{:?}", err);
                        if let Some(wintun) = state.lock().unwrap().wintun.take() {
                            let _ = wintun.kill();
                        }
                    }
                }
            }
            log::info!("sub process started");

            while !rxs.is_empty() {
                let exited: Vec<_> = rxs
                    .iter_mut()
                    .filter_map(|(name, rx)| {
                        let exit = match rx.try_recv() {
                            Ok(CommandEvent::Terminated(payload)) => {
                                log::info!("{} exits with:{:?}", name, payload);
                                true
                            }
                            Ok(CommandEvent::Error(err)) => {
                                log::info!("{} got error:{}", name, err);
                                false
                            }
                            Ok(CommandEvent::Stderr(err)) => {
                                log::info!("{} got stderr:{}", name, err);
                                false
                            }
                            Ok(CommandEvent::Stdout(output)) => {
                                log::info!("{} got stdout:{}", name, output);
                                false
                            }
                            Err(_err) => false,
                            Ok(_) => false,
                        };
                        if exit {
                            let mut state = state.lock().unwrap();
                            match *name {
                                "wintun" => {
                                    state.wintun.take();
                                    if let Some(child) = state.dns.take() {
                                        let _ = child.kill();
                                    }
                                }
                                "dns" => {
                                    set_dns_server(&state);
                                    state.dns.take();
                                    if let Some(child) = state.wintun.take() {
                                        let _ = child.kill();
                                    }
                                }
                                _ => {
                                    log::error!("invalid name:{}", name);
                                }
                            }
                            Some(name.to_string())
                        } else {
                            None
                        }
                    })
                    .collect();
                for name in exited {
                    rxs.remove(name.as_str());
                }
                tokio::time::sleep(Duration::from_millis(66)).await;
            }
            emit_state_update_event(false, window);
            log::info!("sub process exits");
        });
    }
}

fn emit_state_update_event(running: bool, window: Window<Wry>) {
    window.emit("state-update", running).unwrap();
    let app = window.app_handle();
    let state = app.state::<TrojanState>();
    let state = state.lock().unwrap();
    let icon = if running {
        state.running_icon.clone()
    } else {
        state.stopped_icon.clone()
    };
    window.set_icon(icon.clone()).unwrap();
    window.app_handle().tray_handle().set_icon(icon).unwrap();
}

#[tauri::command]
fn init(state: State<TrojanState>) -> Config {
    state.lock().unwrap().config.clone()
}

#[tauri::command]
fn update_speed(state: State<TrojanState>, window: Window<Wry>) {
    let mut state = state.lock().unwrap();
    let (mut rx_speed, mut tx_speed) = state.get_speed().unwrap_or_default();
    let rx_unit = if rx_speed > 1024.0 {
        rx_speed /= 1024.0;
        "MB"
    } else {
        "KB"
    };
    let tx_unit = if tx_speed > 1024.0 {
        tx_speed /= 1024.0;
        "MB"
    } else {
        "KB"
    };
    window
        .set_title(
            format!(
                "Trojan客户端 - 上行:{:.3}{}/下行:{:.3}{}",
                rx_speed, rx_unit, tx_speed, tx_unit
            )
            .as_str(),
        )
        .unwrap();
}

#[tauri::command]
fn stop(state: State<TrojanState>, window: Window<Wry>) {
    log::info!("stop trojan now");
    let mut config = state.lock().unwrap();
    if let Some(child) = config.wintun.take() {
        let _ = child.kill();
        log::info!("trojan stopped");
    } else {
        emit_state_update_event(false, window);
    }
}

fn save_config(config: &Config) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open("config\\config.json")?;
    let data = serde_json::to_string(config)?;
    file.write_all(data.as_bytes())?;
    Ok(())
}

fn init_config() -> Result<Config> {
    let path = Path::new("config\\config.json");
    let config = if path.exists() {
        let file = File::open(path)?;
        let config: Config = serde_json::from_reader(file)?;
        config
    } else {
        Config {
            iface_name: "trojan".into(),
            dns_listen: "127.0.0.1".into(),
            pool_size: 20,
            trust_dns: "8.8.8.8".into(),
            log_level: "Info".into(),
            enable_dns: true,
            ..Config::default()
        }
    };
    Ok(config)
}

fn set_dns_server(state: &TrojanProxy) {
    if state.explicit_dns {
        wintool::adapter::set_dns_server(state.default_dns.clone());
    } else {
        wintool::adapter::set_dns_server("".into());
    }
}

fn main() {
    let path = Path::new("logs");
    if !path.exists() {
        std::fs::create_dir(path).unwrap();
    }
    std::panic::set_hook(Box::new(|info| {
        let trace = Backtrace::new();
        let message = info.to_string();
        if let Ok(mut file) = OpenOptions::new()
            .write(true)
            .append(true)
            .create(true)
            .open("logs\\crash.log")
        {
            let _ = write!(
                &mut file,
                "[{}]client crash with error:{}\ntrace:{:?}\n",
                chrono::Local::now().format("[%Y-%m-%d %H:%M:%S%.6f]"),
                message,
                trace
            );
        }
    }));

    let quit = CustomMenuItem::new("quit".to_string(), "退出");
    let dev = CustomMenuItem::new("dev".to_string(), "开发工具");
    let menu = SystemTrayMenu::new();

    #[cfg(debug_assertions)]
    let menu = menu
        .add_item(dev)
        .add_native_item(SystemTrayMenuItem::Separator);
    let menu = menu.add_item(quit);
    let tray = SystemTray::new().with_menu(menu);

    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![start, init, stop, update_speed])
        .system_tray(tray)
        .plugin(
            tauri_plugin_log::Builder::default()
                .targets([LogTarget::LogDir, LogTarget::Webview, LogTarget::Stdout])
                .format(|callback, args, record| {
                    callback.finish(format_args!(
                        "{}[{}:{}][{}]{}",
                        chrono::Local::now().format("[%Y-%m-%d %H:%M:%S%.6f]"),
                        record.file().unwrap_or("tauri"),
                        record.line().unwrap_or(0),
                        record.level(),
                        args
                    ))
                })
                .level(LevelFilter::Info)
                .build(),
        )
        .plugin(tauri_plugin_single_instance::init(|app, args, cwd| {
            log::info!(
                "app:{}, args:{:?}, cwd:{}",
                app.package_info().name,
                args,
                cwd
            );
        }))
        .manage(Arc::new(Mutex::new(TrojanProxy::new())))
        .on_system_tray_event(|app, event| match event {
            SystemTrayEvent::MenuItemClick { id, .. } => match id.as_str() {
                "quit" => {
                    let state: State<TrojanState> = app.state();
                    let mut state = state.lock().unwrap();
                    if let Some(dns) = state.dns.take() {
                        set_dns_server(&state);
                        let _ = dns.kill();
                        thread::sleep(Duration::from_millis(500));
                    }
                    if let Some(wintun) = state.wintun.take() {
                        let _ = wintun.kill();
                    }
                    std::process::exit(0);
                }
                #[cfg(debug_assertions)]
                "dev" => {
                    let window = app.get_window("main").unwrap();
                    if !window.is_devtools_open() {
                        window.open_devtools();
                    }
                }
                _ => {}
            },
            SystemTrayEvent::DoubleClick { .. } => {
                let window = app.get_window("main").unwrap();
                window.show().unwrap();
                window.set_focus().unwrap();
            }
            _ => {}
        })
        .setup(|app| {
            emit_state_update_event(false, app.get_window("main").unwrap());
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while running tauri application")
        .run(|app, event| match event {
            RunEvent::WindowEvent {
                event: WindowEvent::CloseRequested { api, .. },
                ..
            } => {
                app.get_window("main").unwrap().hide().unwrap();
                api.prevent_close();
            }
            _ => {}
        });
}
