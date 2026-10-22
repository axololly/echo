use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{Encrypted, SnowflakeID};

/// A message sent through Echo.
#[derive(Deserialize, Serialize)]
pub struct Message {
    pub id: SnowflakeID,
    pub replied_to: Option<SnowflakeID>,
    pub author: SnowflakeID,
    pub body: Encrypted<MessageBody>,
    pub sent_at: DateTime<Utc>
}

/// The message's content.
#[derive(Deserialize, Serialize)]
pub struct MessageBody {
    pub content: String
}

/// Temporal parameters for fetching messages.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub enum MessageHistoryParams {
    Before(DateTime<Utc>),
    After(DateTime<Utc>),
    Between(DateTime<Utc>, DateTime<Utc>),
    Latest
}
