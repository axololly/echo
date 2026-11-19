use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{Decode, Encode, Row, postgres::{PgRow, PgTypeInfo}, prelude::FromRow};
use structdiff::{Difference, StructDiff};

use crate::{AssetID, BoxPublicKey, SnowflakeID};

/// The activity status of a given user.
#[derive(Clone, Copy, Debug, Decode, Deserialize, Encode, Eq, PartialEq, Serialize)]
pub enum Activity {
    Online,
    Idle,
    DoNotDisturb,
    Offline
}

impl sqlx::Type<sqlx::Postgres> for Activity {
    fn type_info() -> PgTypeInfo {
        PgTypeInfo::with_name("\"Activity\"")
    }
}

/// An Echo user.
///
/// Their cryptographic information can be found in [`EchoCryptoInfo`].
#[derive(Clone, Debug, Deserialize, Difference, Eq, FromRow, PartialEq, Serialize)]
pub struct User {
    pub id: SnowflakeID,
    pub name: String,
    pub display_name: String,
    pub avatar: Option<AssetID>,
    pub activity: Activity,
    pub status: String,
    pub about_me: String,
    pub show_in_searches: bool,
    pub box_public_key: BoxPublicKey
}

pub type UserDiff = <User as StructDiff>::Diff;

/// Read watermark for a conversation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, FromRow, PartialEq, Serialize, sqlx::Type)]
pub struct ReadWatermark {
    pub message_id: SnowflakeID,
    pub read_at: DateTime<Utc>
}

/// A `sqlx`-compliant version of [`ReadWatermark`].
///
/// `sqlx` does not support flattening an `Option<T>`,
/// so this type must be used to retrieve the data,
/// then it can be converted using the `convert()` method.
#[derive(Clone, Copy, Debug, Deserialize, Eq, FromRow, PartialEq, Serialize, sqlx::Type)]
pub struct SqlxReadWatermark {
    pub last_message_id_read: Option<SnowflakeID>,
    pub last_message_read_at: Option<DateTime<Utc>>
}

impl SqlxReadWatermark {
    pub fn convert(self) -> Option<ReadWatermark> {
        let Self { last_message_id_read, last_message_read_at } = self;

        if let (Some(message_id), Some(read_at)) = (last_message_id_read, last_message_read_at) {
            Some(ReadWatermark { message_id, read_at })
        }
        else {
            None
        }
    }
}

/// A read watermark for a DM.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReadWatermarks {
    pub ours: Option<ReadWatermark>,
    pub theirs: Option<ReadWatermark>
}

impl<'r> FromRow<'r, PgRow> for ReadWatermarks {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let ours = SqlxReadWatermark {
            last_message_id_read: row.try_get("ours_last_message_id_read")?,
            last_message_read_at: row.try_get("ours_last_message_read_at")?
        }.convert();

        let theirs = SqlxReadWatermark {
            last_message_id_read: row.try_get("theirs_last_message_id_read")?,
            last_message_read_at: row.try_get("theirs_last_message_read_at")?
        }.convert();

        Ok(Self { ours, theirs })
    }
}

/// A user's friend, containing the friend's user ID
/// and when they first became friends.
#[derive(Clone, Copy, Debug, Deserialize, FromRow, Serialize)]
pub struct Friend {
    pub user_id: SnowflakeID,
    pub friends_since: DateTime<Utc>,
    pub conversation_id: SnowflakeID,
    #[sqlx(flatten)]
    pub read_watermarks: ReadWatermarks
}

/// A friend request from another user.
#[derive(Clone, Copy, Debug, Deserialize, FromRow, Serialize)]
pub struct IncomingFriendRequest {
    pub sender: SnowflakeID,
    pub sent_at: DateTime<Utc>
}

/// A friend request sent by a user.
#[derive(Clone, Copy, Debug, Deserialize, FromRow, Serialize)]
pub struct OutgoingFriendRequest {
    pub receiver: SnowflakeID,
    pub sent_at: DateTime<Utc>
}

/// A set of incoming and outgoing friend requests for a user.
#[derive(Clone, Debug, Deserialize, FromRow, Serialize)]
pub struct FriendRequests {
    pub incoming: Vec<IncomingFriendRequest>,
    pub outgoing: Vec<OutgoingFriendRequest>
}
