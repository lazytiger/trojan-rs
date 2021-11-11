use async_std::channel::SendError;
use derive_more::{Display, From};

#[derive(From, Display, Debug)]
pub enum TrojanError {
    IOError(async_std::io::Error),
    RecvError(async_std::channel::RecvError),
    InvalidProtocol,
    SendError(String),
}

pub type Result<T> = std::result::Result<T, TrojanError>;

impl<T> From<async_std::channel::SendError<T>> for TrojanError {
    fn from(err: SendError<T>) -> Self {
        TrojanError::SendError(err.to_string())
    }
}
