use async_std::channel::SendError;
use derive_more::{Display, From};
use std::sync::{MutexGuard, PoisonError};

#[derive(From, Display, Debug)]
pub enum TrojanError {
    IOError(async_std::io::Error),
    RecvError(async_std::channel::RecvError),
    InvalidProtocol,
    #[from(ignore)]
    SendError(String),
    #[from(ignore)]
    PoisonError(String),
}

pub type Result<T> = std::result::Result<T, TrojanError>;

impl<T> From<async_std::channel::SendError<T>> for TrojanError {
    fn from(err: SendError<T>) -> Self {
        TrojanError::SendError(err.to_string())
    }
}

impl<T> From<std::sync::PoisonError<T>> for TrojanError {
    fn from(err: PoisonError<T>) -> Self {
        TrojanError::PoisonError(err.to_string())
    }
}
