#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
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
    image::Image,
    menu::{Menu, MenuItem},
    path::BaseDirectory,
    tray::{MouseButton, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, Manager, RunEvent, State, WebviewWindow, WindowEvent, Wry,
};
use tauri_plugin_log::{Target, TargetKind};
use tauri_plugin_shell::{
    process::{CommandChild, CommandEvent},
    ShellExt,
};

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
    pub enable_dns: bool,
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
    running_icon: Image<'static>,
    stopped_icon: Image<'static>,
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
            running_icon: Image::from_bytes(include_bytes!("../icons/icon.ico")).unwrap(),
            stopped_icon: Image::from_bytes(include_bytes!("../icons/icon_gray.png")).unwrap(),
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
fn start(config: Config, state: State<TrojanState>, window: WebviewWindow<Wry>) {
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
                .path()
                .resolve("config/ipset.txt", BaseDirectory::Resource)
                .unwrap();
            let config_wintun = window
                .app_handle()
                .path()
                .resolve("libs/wintun.dll", BaseDirectory::Resource)
                .unwrap();
            let mut args = vec![
                "-l",
                "logs\\wintun.log",
                "-L",
                config.log_level_str(),
                "-a",
                "127.0.0.1:60080",
                "-p",
                config.server_auth.as_str(),
                "awintun",
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
            args.push("--route-ipset");
            args.push(config_ipset.to_str().unwrap());
            log::info!("{:?}", args);
            let mut rxs = HashMap::new();
            match window
                .app_handle()
                .shell()
                .sidecar("trojan")
                .unwrap()
                .args(args)
                .spawn()
            {
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
                    .path()
                    .resolve("config/domain.txt", BaseDirectory::Resource)
                    .unwrap();
                let config_hosts = window
                    .app_handle()
                    .path()
                    .resolve("config/hosts.txt", BaseDirectory::Resource)
                    .unwrap();
                let args = vec![
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
                log::info!("{:?}", args);
                match window
                    .app_handle()
                    .shell()
                    .sidecar("trojan")
                    .unwrap()
                    .args(args)
                    .spawn()
                {
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
                                log::info!("{} got stderr:{}", name, String::from_utf8_lossy(&err));
                                false
                            }
                            Ok(CommandEvent::Stdout(output)) => {
                                log::info!(
                                    "{} got stdout:{}",
                                    name,
                                    String::from_utf8_lossy(&output)
                                );
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

fn emit_state_update_event(running: bool, window: WebviewWindow<Wry>) {
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
    if let Some(tray) = window.app_handle().tray_by_id("main") {
        tray.set_icon(Some(icon)).unwrap();
    }
}

#[tauri::command]
fn init(state: State<TrojanState>) -> Config {
    state.lock().unwrap().config.clone()
}

#[tauri::command]
fn update_speed(state: State<TrojanState>, window: WebviewWindow<Wry>) {
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
fn stop(state: State<TrojanState>, window: WebviewWindow<Wry>) {
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


fn load_domains() -> Result<Vec<String>> {
    let path = Path::new("config\\domain.txt");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut domains = Vec::new();
    for line in reader.lines() {
        let domain = line?.trim().to_string();
        if !domain.is_empty() {
            domains.push(domain);
        }
    }
    Ok(domains)
}

fn save_domains(domains: &[String]) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open("config\\domain.txt")?;
    for domain in domains {
        writeln!(file, "{}", domain)?;
    }
    Ok(())
}

#[tauri::command]
fn search_domain(key: String) -> Vec<String> {
    match load_domains() {
        Ok(domains) => domains
            .into_iter()
            .filter(|domain| domain.contains(&key))
            .take(10)
            .collect(),
        Err(err) => {
            log::error!("search domain failed:{:?}", err);
            Vec::new()
        }
    }
}

#[tauri::command]
fn add_domain(key: String) {
    let key = key.trim().to_string();
    if key.is_empty() {
        return;
    }
    match load_domains() {
        Ok(mut domains) => {
            if !domains.iter().any(|domain| domain == &key) {
                domains.push(key);
                if let Err(err) = save_domains(&domains) {
                    log::error!("save domains failed:{:?}", err);
                }
            }
        }
        Err(err) => log::error!("load domains failed:{:?}", err),
    }
}

#[tauri::command]
fn remove_domain(key: String) {
    match load_domains() {
        Ok(mut domains) => {
            let old_len = domains.len();
            domains.retain(|domain| domain != &key);
            if domains.len() != old_len {
                if let Err(err) = save_domains(&domains) {
                    log::error!("save domains failed:{:?}", err);
                }
            }
        }
        Err(err) => log::error!("load domains failed:{:?}", err),
    }
}
fn set_dns_server(state: &TrojanProxy) {
    if state.explicit_dns {
        wintool::adapter::set_dns_server(state.default_dns.clone());
    } else {
        wintool::adapter::set_dns_server("".into());
    }
}

fn quit_app(app: &AppHandle<Wry>) {
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

fn show_main_window(app: &AppHandle<Wry>) {
    if let Some(window) = app.get_webview_window("main") {
        window.show().unwrap();
        window.set_focus().unwrap();
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

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_http::init())
        .plugin(tauri_plugin_fs::init())
        .invoke_handler(tauri::generate_handler![start, init, stop, update_speed, search_domain, add_domain, remove_domain])
        .plugin(
            tauri_plugin_log::Builder::default()
                .targets([
                    Target::new(TargetKind::LogDir { file_name: None }),
                    Target::new(TargetKind::Webview),
                    Target::new(TargetKind::Stdout),
                ])
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
        .setup(|app| {
            let quit = MenuItem::with_id(app, "quit", "退出", true, None::<&str>)?;
            let menu = Menu::new(app)?;

            #[cfg(debug_assertions)]
            {
                let dev = MenuItem::with_id(app, "dev", "开发工具", true, None::<&str>)?;
                let separator = PredefinedMenuItem::separator(app)?;
                menu.append_items(&[&dev, &separator])?;
            }

            menu.append(&quit)?;
            TrayIconBuilder::with_id("main")
                .icon(Image::from_bytes(include_bytes!("../icons/icon.png"))?)
                .icon_as_template(true)
                .menu(&menu)
                .on_menu_event(|app, event| {
                    if event.id() == "quit" {
                        quit_app(app);
                    }
                    #[cfg(debug_assertions)]
                    if event.id() == "dev" {
                        if let Some(window) = app.get_webview_window("main") {
                            if !window.is_devtools_open() {
                                window.open_devtools();
                            }
                        }
                    }
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::DoubleClick {
                        button: MouseButton::Left,
                        ..
                    } = event
                    {
                        show_main_window(tray.app_handle());
                    }
                })
                .build(app)?;

            emit_state_update_event(false, app.get_webview_window("main").unwrap());
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while running tauri application")
        .run(|app, event| match event {
            RunEvent::WindowEvent {
                event: WindowEvent::CloseRequested { api, .. },
                ..
            } => {
                app.get_webview_window("main").unwrap().hide().unwrap();
                api.prevent_close();
            }
            _ => {}
        });
}
