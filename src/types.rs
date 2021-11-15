use derive_more::{Display, From};

#[derive(From, Display, Debug)]
pub enum TrojanError {
    StdIoError(std::io::Error),
}

pub type Result<T> = std::result::Result<T, TrojanError>;
