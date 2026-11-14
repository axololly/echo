use serde::{Deserialize, Serialize};
use sqlx::prelude::FromRow;

use crate::{AssetID, SnowflakeID};

/// An emoji uploaded to a group chat.
#[derive(Clone, Debug, Deserialize, FromRow, Eq, PartialEq, Serialize)]
pub struct Emoji {
    pub id: SnowflakeID,
    pub group_id: SnowflakeID,
    pub name: String,
    pub asset_id: AssetID
}

/// A reaction attached to a message.
#[derive(Clone, Debug, Deserialize, FromRow, Serialize)]
pub struct Reaction {
    pub message_id: SnowflakeID,
    pub author: SnowflakeID,
    #[sqlx(flatten)]
    pub emoji: Emoji
}
