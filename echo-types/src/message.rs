use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::prelude::FromRow;

use crate::{AssetID, Encrypted, SnowflakeID};

/// A message sent through Echo.
#[derive(Clone, Deserialize, FromRow, Serialize)]
pub struct Message {
    pub id: SnowflakeID,
    pub conversation_id: SnowflakeID,
    #[sqlx(rename = "parent_id")]
    pub replied_to: Option<SnowflakeID>,
    pub author: SnowflakeID,
    #[sqlx(rename = "blob")]
    pub body: Encrypted<MessageBody>,
    pub sent_at: DateTime<Utc>,
    pub pinned: bool,
    pub attachments: Vec<AssetID>
}

/// The message's content.
#[derive(Clone, Deserialize, Serialize)]
pub struct MessageBody { // TODO: see if this can be replaced with just String
    pub content: String
}

/// An attachment on a message.
#[derive(Clone, Deserialize, Serialize)]
pub struct Attachment { // TODO: make just the data encrypted
    pub filename: String,
    pub data: Vec<u8>
}
