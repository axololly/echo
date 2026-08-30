use serde::{Deserialize, Serialize};

use crate::{Message, SnowflakeID};

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub enum SystemEvent {
    MemberJoined(SnowflakeID),
    MemberLeft(SnowflakeID),
    MemberKicked(SnowflakeID),
    MemberBanned(SnowflakeID)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Event {
    SendMessage(Message),
    System(SystemEvent)
}
