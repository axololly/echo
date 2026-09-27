use rootcause::Result;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::routes::UserRouteError;

/// An error related to accessing a route.
#[derive(Clone, Copy, Debug, Deserialize, Error, Serialize)]
#[repr(u8)]
pub enum RouteError {
    #[error("database error")]
    Database,

    #[error("invalid incoming data")]
    InvalidData,

    #[error("transport error")]
    Transport,

    #[error("unknown resource")]
    UnknownResource,

    #[error("user route error")]
    User(#[from] UserRouteError)
}

pub type RouteResult<T> = Result<T, RouteError>;
