use serde::{Deserialize, Serialize};

use crate::{Encrypted, SnowflakeID};

/// A message sent through Echo.
#[derive(Deserialize, Serialize)]
pub struct Message {
    pub id: SnowflakeID,
    pub replied_to: Option<SnowflakeID>,
    pub author: SnowflakeID,
    pub body: Encrypted<MessageBody>
}

/// The message's content.
#[derive(Deserialize, Serialize)]
pub struct MessageBody {
    pub content: String
}
