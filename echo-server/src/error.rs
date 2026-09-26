use rootcause::Result;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// An error related to accessing a route.
#[derive(Clone, Copy, Debug, Deserialize, Error, Serialize)]
#[repr(u8)]
pub enum RouteError {
    #[error("database error")]
    Database,

    #[error("invalid incoming data")]
    InvalidData,

    #[error("unknown resource")]
    UnknownResource
}

pub type RouteResult<T> = Result<T, RouteError>;
