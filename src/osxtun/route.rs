#[cfg(target_os = "macos")]
use crate::types::Result;
use std::net::Ipv4Addr;
#[cfg(target_os = "macos")]
use std::process::Command;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteConfig {
    pub interface: String,
    pub gateway: Ipv4Addr,
    pub server_ip: Ipv4Addr,
    pub tun_addr: Ipv4Addr,
    pub tun_peer: Ipv4Addr,
    pub mtu: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandSpec {
    pub program: String,
    pub args: Vec<String>,
    pub ignore_failure: bool,
}

impl CommandSpec {
    fn new(program: &str, args: Vec<String>) -> Self {
        Self {
            program: program.to_string(),
            args,
            ignore_failure: false,
        }
    }

    fn ignore_failure(mut self) -> Self {
        self.ignore_failure = true;
        self
    }
}

pub fn build_apply_commands(config: &RouteConfig) -> Vec<CommandSpec> {
    vec![
        CommandSpec::new(
            "ifconfig",
            vec![
                config.interface.clone(),
                "inet".to_string(),
                config.tun_addr.to_string(),
                config.tun_peer.to_string(),
                "mtu".to_string(),
                config.mtu.to_string(),
                "up".to_string(),
            ],
        ),
        CommandSpec::new(
            "route",
            vec![
                "-n".to_string(),
                "add".to_string(),
                "-host".to_string(),
                config.server_ip.to_string(),
                config.gateway.to_string(),
            ],
        ),
        delete_split_route("0.0.0.0/1", &config.interface).ignore_failure(),
        delete_split_route("128.0.0.0/1", &config.interface).ignore_failure(),
        add_split_route("0.0.0.0/1", &config.interface),
        add_split_route("128.0.0.0/1", &config.interface),
    ]
}

pub fn build_cleanup_commands(config: &RouteConfig) -> Vec<CommandSpec> {
    vec![
        delete_split_route("0.0.0.0/1", &config.interface).ignore_failure(),
        delete_split_route("128.0.0.0/1", &config.interface).ignore_failure(),
        CommandSpec::new(
            "route",
            vec![
                "-n".to_string(),
                "delete".to_string(),
                "-host".to_string(),
                config.server_ip.to_string(),
                config.gateway.to_string(),
            ],
        )
        .ignore_failure(),
    ]
}

fn add_split_route(cidr: &str, interface: &str) -> CommandSpec {
    CommandSpec::new(
        "route",
        vec![
            "-n".to_string(),
            "add".to_string(),
            "-net".to_string(),
            cidr.to_string(),
            "-interface".to_string(),
            interface.to_string(),
        ],
    )
}

fn delete_split_route(cidr: &str, interface: &str) -> CommandSpec {
    CommandSpec::new(
        "route",
        vec![
            "-n".to_string(),
            "delete".to_string(),
            "-net".to_string(),
            cidr.to_string(),
            "-interface".to_string(),
            interface.to_string(),
        ],
    )
}

pub fn parse_default_gateway(output: &str) -> Option<Ipv4Addr> {
    output.lines().find_map(|line| {
        let line = line.trim();
        let gateway = line.strip_prefix("gateway:")?.trim();
        gateway.parse().ok()
    })
}

#[cfg(target_os = "macos")]
pub fn default_gateway() -> Result<Ipv4Addr> {
    let output = Command::new("route")
        .args(["-n", "get", "default"])
        .output()?;
    if !output.status.success() {
        return Err(crate::types::TrojanError::Custom(format!(
            "route -n get default failed:{}",
            output.status
        )));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    parse_default_gateway(&text)
        .ok_or_else(|| crate::types::TrojanError::Custom("default gateway not found".to_string()))
}

#[cfg(target_os = "macos")]
pub fn run_commands(commands: &[CommandSpec]) -> Result<()> {
    for command in commands {
        log::info!("run command: {} {:?}", command.program, command.args);
        let status = Command::new(&command.program)
            .args(&command.args)
            .status()?;
        if !status.success() && !command.ignore_failure {
            return Err(crate::types::TrojanError::Custom(format!(
                "command failed: {} {:?}, status:{}",
                command.program, command.args, status
            )));
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub struct RouteGuard {
    config: RouteConfig,
}

#[cfg(target_os = "macos")]
impl RouteGuard {
    pub fn apply(config: RouteConfig) -> Result<Self> {
        run_commands(&build_apply_commands(&config))?;
        Ok(Self { config })
    }
}

#[cfg(target_os = "macos")]
impl Drop for RouteGuard {
    fn drop(&mut self) {
        if let Err(err) = run_commands(&build_cleanup_commands(&self.config)) {
            log::error!("cleanup osxtun route failed:{:?}", err);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::{build_apply_commands, build_cleanup_commands, parse_default_gateway, RouteConfig};

    #[test]
    fn apply_commands_add_server_route_before_split_default_routes() {
        let config = RouteConfig {
            interface: "utun7".to_string(),
            gateway: Ipv4Addr::new(192, 168, 31, 1),
            server_ip: Ipv4Addr::new(8, 8, 8, 8),
            tun_addr: Ipv4Addr::new(10, 255, 0, 2),
            tun_peer: Ipv4Addr::new(10, 255, 0, 1),
            mtu: 1400,
        };

        let commands = build_apply_commands(&config);
        let args: Vec<Vec<String>> = commands.into_iter().map(|cmd| cmd.args).collect();

        assert_eq!(
            args,
            vec![
                vec![
                    "utun7",
                    "inet",
                    "10.255.0.2",
                    "10.255.0.1",
                    "mtu",
                    "1400",
                    "up"
                ],
                vec!["-n", "add", "-host", "8.8.8.8", "192.168.31.1"],
                vec!["-n", "delete", "-net", "0.0.0.0/1", "-interface", "utun7"],
                vec!["-n", "delete", "-net", "128.0.0.0/1", "-interface", "utun7"],
                vec!["-n", "add", "-net", "0.0.0.0/1", "-interface", "utun7"],
                vec!["-n", "add", "-net", "128.0.0.0/1", "-interface", "utun7"],
            ]
        );
    }

    #[test]
    fn cleanup_commands_remove_split_defaults_and_server_route() {
        let config = RouteConfig {
            interface: "utun7".to_string(),
            gateway: Ipv4Addr::new(192, 168, 31, 1),
            server_ip: Ipv4Addr::new(8, 8, 8, 8),
            tun_addr: Ipv4Addr::new(10, 255, 0, 2),
            tun_peer: Ipv4Addr::new(10, 255, 0, 1),
            mtu: 1400,
        };

        let commands = build_cleanup_commands(&config);
        let args: Vec<Vec<String>> = commands.into_iter().map(|cmd| cmd.args).collect();

        assert_eq!(
            args,
            vec![
                vec!["-n", "delete", "-net", "0.0.0.0/1", "-interface", "utun7"],
                vec!["-n", "delete", "-net", "128.0.0.0/1", "-interface", "utun7"],
                vec!["-n", "delete", "-host", "8.8.8.8", "192.168.31.1"],
            ]
        );
    }

    #[test]
    fn parses_default_gateway_from_route_output() {
        let output = "   route to: default\ndestination: default\n       mask: default\n    gateway: 192.168.31.1\n  interface: en0\n";
        assert_eq!(
            parse_default_gateway(output),
            Some(Ipv4Addr::new(192, 168, 31, 1))
        );
    }
}
