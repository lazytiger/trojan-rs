use derive_more::{Display, From};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Default)]
pub(crate) struct Config {
    pub enable_dns: bool,
    pub log_level: u8,
    pub password: String,
    pub iface_name: String,
    pub host_name: String,
    pub enable_ipset: bool,
    pub inverse_route: bool,
    pub pool_size: u32,
    pub poison_dns: String,
    pub trust_dns: String,
}

#[derive(From, Debug, Display)]
pub enum Error {
    StdIo(std::io::Error),
    SerdeJson(serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
