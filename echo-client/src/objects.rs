use chrono::TimeDelta;
use dashmap::{DashMap, DashSet};
use echo_types::{Emoji, Friend, Group, Message as EchoMessage, ReadWatermark, Secret, SnowflakeID, User};
use vodozemac::megolm::GroupSession;

/// A centralised object store.
#[derive(Default)]
pub struct ObjectStore {
    pub users: DashMap<SnowflakeID, User>,
    pub groups: GroupStore,
    pub emojis: DashMap<SnowflakeID, Emoji>,
    pub conversations: ConversationStore,
    pub messages: MessageStore,
    pub friends: DashMap<SnowflakeID, Friend>
}

/// A store for conversation sessions and messages in conversations.
#[derive(Default)]
pub struct ConversationStore {
    pub messages: DashMap<SnowflakeID, DashSet<SnowflakeID>>,
    pub pinned: DashMap<SnowflakeID, DashSet<SnowflakeID>>,
    pub sessions: DashMap<SnowflakeID, GroupSession>,
    pub read_watermarks: DashMap<SnowflakeID, DashMap<SnowflakeID, ReadWatermark>>,
    pub default_message_timers: DashMap<SnowflakeID, Option<TimeDelta>>
}

/// A store for groups and their emojis.
#[derive(Default)]
pub struct GroupStore {
    pub objects: DashMap<SnowflakeID, Group>,
    pub emojis: DashMap<SnowflakeID, DashSet<SnowflakeID>>
}

/// A store for messages and message secrets.
#[derive(Default)]
pub struct MessageStore {
    pub objects: DashMap<SnowflakeID, EchoMessage>,
    pub secrets: DashMap<SnowflakeID, Secret>
}
