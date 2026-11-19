use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::prelude::FromRow;

use crate::{AssetID, Encrypted, Reaction, SnowflakeID};

/// A message sent through Echo.
#[derive(Clone, Deserialize, FromRow, Serialize)]
pub struct Message {
    pub id: SnowflakeID,
    pub conversation_id: SnowflakeID,
    #[sqlx(rename = "parent_id")]
    pub replied_to: Option<SnowflakeID>,
    pub author: SnowflakeID,
    #[sqlx(rename = "blob")]
    pub body: Encrypted<String>,
    pub sent_at: DateTime<Utc>,
    pub pinned: bool,
    pub delete_at: Option<DateTime<Utc>>,
    #[sqlx(json)]
    pub attachments: Vec<Attachment>,
    #[sqlx(json)]
    pub reactions: Vec<Reaction>
}

/// An attachment on a message.
#[derive(Clone, Deserialize, FromRow, Serialize)]
pub struct Attachment {
    pub filename: String,
    pub asset_id: AssetID
}

/// An attachment uploaded for a message.
#[derive(Clone, Deserialize, Serialize)]
pub struct UploadedAttachment {
    pub filename: String,
    pub data: Encrypted<Vec<u8>>
}
