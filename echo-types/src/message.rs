use serde::{Deserialize, Serialize};

use crate::{Encrypted, SnowflakeID};

#[derive(Deserialize, Serialize)]
pub struct Message {
    pub id: SnowflakeID,
    pub author: SnowflakeID,
    pub body: Encrypted<MessageBody>
}

#[derive(Deserialize, Serialize)]
pub struct MessageBody {
    pub content: String
}
