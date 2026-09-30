use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{Decode, Encode, postgres::PgTypeInfo, prelude::FromRow};
use vodozemac::olm::AccountPickle;

use crate::{AssetID, Encrypted, OlmPublicKey, PasswordProtected, Secret, SignatureVerifier, SnowflakeID};

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

/// The client-side settings a user has on their account.
///
/// These are stored encrypted on the server and fetched
/// when necessary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserSettings {
    /// How long in seconds after going inactive
    /// before a user is logged out.
    pub logout_after: u64,

    /// Whether or not to send typing indicators
    /// to the server.
    pub enable_typing_indicators: bool,

    /// Whether or not to send read receipts to
    /// the server.
    pub enable_read_receipts: bool,

    /// Who to automatically reject future friend
    /// requests from.
    pub ignore_future_requests_from: Vec<SnowflakeID>
}

/// The user's state.
///
/// This only contains their settings for now,
/// but this will eventually include DM sessions
/// and group sessions with other people.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserState {
    pub settings: UserSettings,
    // TODO: UserState involving the sessions with other people
}

/// An Echo user.
#[derive(Clone, Debug, Deserialize, Eq, FromRow, PartialEq, Serialize)]
pub struct User {
    pub id: SnowflakeID,
    pub name: String,
    pub display_name: String,
    pub avatar: AssetID,
    pub activity: Activity,
    pub status: String,
    pub about_me: String,
    #[sqlx(rename = "encrypted_secret")]
    pub secret: PasswordProtected<Secret>,
    #[sqlx(rename = "encrypted_state")]
    pub state: Encrypted<UserState>,
    pub signature_verifier: SignatureVerifier,
    pub olm_account: Encrypted<AccountPickle>,
    pub olm_public_key: OlmPublicKey
}

/// A user's friend, containing the friend's user ID
/// and when they first became friends.
#[derive(Clone, Copy, Deserialize, FromRow, Serialize)]
pub struct Friend {
    pub id: SnowflakeID,
    pub friends_since: DateTime<Utc>
}

/// A request to become friends with another user.
#[derive(Clone, Copy, Deserialize, FromRow, Serialize)]
pub struct FriendRequest {
    pub sender: SnowflakeID,
    pub sent_at: DateTime<Utc>
}
