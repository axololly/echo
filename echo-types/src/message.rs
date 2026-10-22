use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::prelude::FromRow;

use crate::{Encrypted, SnowflakeID};

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
    pub pinned: bool
}

/// The message's content.
#[derive(Clone, Deserialize, Serialize)]
pub struct MessageBody {
    pub content: String
}
