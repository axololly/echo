use serde::{Deserialize, Serialize};
use sqlx::{Decode, Encode, postgres::PgTypeInfo, prelude::FromRow};

use crate::{AssetID, Encrypted, PasswordProtected, Secret, SignatureVerifier, SnowflakeID};

#[derive(Debug, Decode, Deserialize, Encode, Eq, PartialEq, Serialize)]
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

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserSettings {
    pub cache_secret_for: u64, // seconds
    pub logout_after: u64, // seconds
    pub enable_typing_indicators: bool,
    pub enable_read_receipts: bool,
    pub ignore_future_requests_from: Vec<SnowflakeID>
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserState {
    pub settings: UserSettings,
    // TODO: UserState involving the sessions with other people
}

#[derive(Debug, Deserialize, Eq, FromRow, PartialEq, Serialize)]
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
    pub signature_verifier: SignatureVerifier
}
