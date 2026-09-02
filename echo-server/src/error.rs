use rootcause::Result;
use serde::{Deserialize, Serialize};
use thiserror::Error as ErrorMacro;

use crate::routes::{GroupRouteError, UserRouteError};

#[derive(Clone, Copy, Debug, Deserialize, ErrorMacro, Serialize)]
#[repr(u8)]
pub enum RouteError {
    #[error("database error")]
    Database,

    #[error("invalid incoming data")]
    InvalidData,

    #[error("user failed to authenticate themselves")]
    UserAuthFailed,

    #[error("transport error")]
    Transport,

    #[error("ratelimit reached")]
    RatelimitReached,

    #[error("unknown resource")]
    UnknownResource,

    #[error("user route error")]
    User(#[from] UserRouteError),

    #[error("group route error")]
    Group(#[from] GroupRouteError)
}

pub type RouteResult<T> = Result<T, RouteError>;
