use serde::{Deserialize, Serialize};

use crate::{Message, Reaction, SnowflakeID};

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
    EditMessage(SnowflakeID, Message),
    DeleteMessage(SnowflakeID),
    System(SystemEvent),
    AddReaction(Reaction),
    RemoveReaction(Reaction)
}
