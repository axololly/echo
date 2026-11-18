use quinn::VarInt;
use rootcause::Result;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::routes::{ConversationRouteError, GroupRouteError, MessagesRouteError, UserRouteError};

/// An error related to accessing a route.
#[derive(Clone, Debug, Deserialize, Error, Serialize)]
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

    #[error("route requires authentication")]
    NeedsAuthentication,

    #[error("data is too large, exceeded {_0} bytes")]
    DataTooLarge(u64),

    #[error("user route error")]
    User(#[from] UserRouteError),

    #[error("group route error")]
    Group(#[from] GroupRouteError),

    #[error("messages route error")]
    Messages(#[from] MessagesRouteError),

    #[error("conversation route error")]
    Conversation(#[from] ConversationRouteError)
}

pub type RouteResult<T> = Result<T, RouteError>;

/// Too much data was sent by the client, causing the server to close the stream.
pub const DATA_TOO_LARGE: VarInt = VarInt::from_u32(100);

/// Another user logged in from another location.
pub const ANOTHER_DEVICE_LOGGED_IN: VarInt = VarInt::from_u32(101);
