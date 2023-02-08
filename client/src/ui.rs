use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::Path,
    process::{Child, Command},
    time::Instant,
};

use eframe::{
    egui::{
        CentralPanel, Color32, ComboBox, Context, Grid, RichText, Slider, TextEdit, TopBottomPanel,
        Widget, Window,
    },
    App, Frame,
};

use crate::types::{Config, Result};

pub struct MainUi {
    config: Config,
    wintun: Option<Child>,
    wintun_start_time: Instant,
    dns: Option<Child>,
    show_log: bool,
}

fn init_config() -> Result<Config> {
    let path = Path::new("config.json");
    let config = if path.exists() {
        let file = File::open(path)?;
        let config: Config = serde_json::from_reader(file)?;
        config
    } else {
        Config::default()
    };
    Ok(config)
}

impl MainUi {
    pub fn new() -> Self {
        let config = match init_config() {
            Ok(config) => config,
            Err(err) => {
                log::error!("init config failed:{}", err);
                Config::default()
            }
        };
        MainUi {
            config,
            wintun: None,
            dns: None,
            wintun_start_time: Instant::now(),
            show_log: false,
        }
    }

    pub(crate) fn start(&mut self) {
        if self.wintun.is_some() || self.dns.is_some() || !self.is_config_ok() {
            return;
        }

        let mut cmd = Command::new("bin\\trojan.exe");
        let dns = self.config.poison_dns.clone() + ":53";
        cmd.arg("-l")
            .arg("logs\\wintun.log")
            .arg("-L")
            .arg(self.config.log_level.to_string().as_str())
            .arg("-a")
            .arg("127.0.0.1:60080")
            .arg("-p")
            .arg(self.config.password.as_str())
            .arg("wintun")
            .arg("-n")
            .arg(self.config.iface_name.as_str())
            .arg("-H")
            .arg(self.config.host_name.as_str())
            .arg("--dns-server-addr")
            .arg(dns.as_str())
            .arg("-P")
            .arg(self.config.pool_size.to_string().as_str());
        if self.config.enable_ipset {
            cmd.arg("--route-ipset").arg("config\\ipset.txt");
            if self.config.inverse_route {
                cmd.arg("--inverse-route");
            }
        }

        log::debug!("cmd:{:?}", cmd);

        match cmd.spawn() {
            Ok(child) => {
                self.wintun.replace(child);
                self.wintun_start_time = Instant::now();
                log::info!("wintun started");
            }
            Err(err) => {
                log::error!("start wintun failed:{}", err);
            }
        }
    }

    fn check_status(&mut self) {
        if self.dns.is_none()
            && self.config.enable_dns
            && self.wintun.is_some()
            && self.wintun_start_time.elapsed().as_secs() > 10
        {
            let mut cmd = Command::new("bin\\trojan.exe");
            cmd.arg("-l")
                .arg("logs\\dns.log")
                .arg("-L")
                .arg(self.config.log_level.to_string().as_str())
                .arg("-a")
                .arg("127.0.0.1:60080")
                .arg("-p")
                .arg(self.config.password.as_str())
                .arg("dns")
                .arg("-n")
                .arg(self.config.iface_name.as_str())
                .arg("--blocked-domain-list")
                .arg("config\\domain.txt")
                .arg("--poisoned-dns")
                .arg(self.config.poison_dns.as_str());
            if !self.config.enable_ipset {
                cmd.arg("--add-route");
            }

            log::debug!("{:?}", cmd);

            match cmd.spawn() {
                Ok(child) => {
                    self.dns.replace(child);
                    log::info!("dns started");
                }
                Err(err) => {
                    log::error!("dns start failed:{}", err);
                }
            }
        }

        if let Some(wintun) = &mut self.wintun {
            if let Ok(None) = wintun.try_wait() {
            } else {
                let err = wintun
                    .stderr
                    .take()
                    .map(|err| std::io::read_to_string(err).unwrap_or_default())
                    .unwrap_or_default();
                log::error!("wintun stopped with err:{}", err);
                self.wintun.take();
                self.stop();
            }
        }

        if let Some(dns) = &mut self.dns {
            if let Ok(None) = dns.try_wait() {
            } else {
                let err = dns
                    .stderr
                    .take()
                    .map(|err| std::io::read_to_string(err).unwrap_or_default())
                    .unwrap_or_default();
                log::error!("dns stopped with err:{}", err);
                self.dns.take();
                self.stop();
            }
        }
    }

    fn stop(&mut self) {
        if let Some(wintun) = &mut self.wintun {
            wintun.kill().unwrap();
            log::error!("wintun is killed");
        }
        if let Some(dns) = &mut self.dns {
            log::error!("dns is killed");
            dns.kill().unwrap();
        }
        self.wintun.take();
        self.dns.take();
    }

    pub(crate) fn get_log_level(level: u8) -> &'static str {
        match level {
            0 => "Trace",
            1 => "Debug",
            2 => "Info",
            3 => "Warn",
            4 => "Error",
            _ => "Off",
        }
    }

    pub fn btn_label(&self) -> &'static str {
        if self.wintun.is_some() {
            "                       停  止                       "
        } else if self.is_config_ok() {
            "                       开  始                       "
        } else {
            "                  缺少配置                     "
        }
    }

    pub(crate) fn save_config(&self) {
        if let Some(err) = serde_json::to_string(&self.config)
            .map(|s| {
                OpenOptions::new()
                    .create(true)
                    .truncate(true)
                    .write(true)
                    .open("config.json")
                    .map(|mut f| f.write_all(s.as_bytes()))
            })
            .err()
        {
            log::error!("save config failed:{}", err);
        }
    }
    fn is_config_ok(&self) -> bool {
        !self.config.host_name.is_empty()
            && !self.config.iface_name.is_empty()
            && !self.config.password.is_empty()
            && !self.config.poison_dns.is_empty()
            && if self.config.enable_dns {
                !self.config.trust_dns.is_empty()
            } else {
                true
            }
    }
}

impl App for MainUi {
    fn update(&mut self, ctx: &Context, _frame: &mut Frame) {
        self.check_status();
        TopBottomPanel::bottom("bottom").show(ctx, |ui| {
            if ui
                .button(
                    RichText::new(self.btn_label())
                        .size(32.0)
                        .color(Color32::WHITE)
                        .background_color(Color32::DARK_BLUE),
                )
                .clicked()
            {
                if !self.is_config_ok() {
                } else if self.wintun.is_none() {
                    self.save_config();
                    self.start();
                } else {
                    self.stop();
                }
            }
        });
        TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal_centered(|ui| {
                if ui.button("保存配置").clicked() {
                    self.save_config();
                }
                ui.checkbox(&mut self.show_log, "显示日志");
            });
        });
        CentralPanel::default().show(ctx, |ui| {
            if self.show_log {
                Window::new("log")
                    .auto_sized()
                    .show(ctx, egui_logger::logger_ui);
                return;
            }
            Grid::new("grid")
                .num_columns(2)
                .spacing([30.0, 15.0])
                .striped(true)
                .show(ui, |ui| {
                    ui.label("虚拟网卡名：");
                    ui.text_edit_singleline(&mut self.config.iface_name);
                    ui.end_row();

                    ui.label("服务器域名：");
                    ui.text_edit_singleline(&mut self.config.host_name);
                    ui.end_row();

                    ui.label("服务器密码：");
                    TextEdit::singleline(&mut self.config.password)
                        .password(true)
                        .ui(ui);
                    ui.end_row();

                    ui.label("DNS服务器：");
                    ui.text_edit_singleline(&mut self.config.poison_dns);
                    ui.end_row();

                    ui.label("日志级别：");
                    ComboBox::from_label("")
                        .selected_text(Self::get_log_level(self.config.log_level))
                        .show_ui(ui, |ui| {
                            for i in 0..6 {
                                ui.selectable_value(
                                    &mut self.config.log_level,
                                    i,
                                    Self::get_log_level(i),
                                );
                            }
                        });
                    ui.end_row();

                    ui.label("连接池大小：");
                    Slider::new(&mut self.config.pool_size, 0..=20).ui(ui);
                    ui.end_row();

                    ui.label("使用全局代理：");
                    ui.checkbox(&mut self.config.enable_ipset, "");
                    ui.end_row();

                    ui.label("反转代理地址：");
                    ui.checkbox(&mut self.config.inverse_route, "");
                    ui.end_row();

                    ui.label("使用信任代理：");
                    ui.checkbox(&mut self.config.enable_dns, "");
                    ui.end_row();

                    if self.config.enable_dns {
                        ui.label("信任DNS服务器：");
                        ui.text_edit_singleline(&mut self.config.trust_dns);
                        ui.end_row();
                    }
                });
        });
    }
}
