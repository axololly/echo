use serde::{Deserialize, Serialize};
use sqlx::{Decode, Encode, postgres::PgTypeInfo, prelude::FromRow};
use vodozemac::olm::AccountPickle;

use crate::{AssetID, Encrypted, PasswordProtected, Secret, SignatureVerifier, SnowflakeID};

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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserSettings {
    pub cache_secret_for: u64, // seconds
    pub logout_after: u64, // seconds
    pub enable_typing_indicators: bool,
    pub enable_read_receipts: bool
}

#[derive(Clone, Debug, Deserialize, Eq, FromRow, PartialEq, Serialize)]
pub struct User {
    pub id: SnowflakeID,
    pub name: String,
    pub display_name: String,
    pub avatar: AssetID,
    pub activity: Activity,
    pub status: String,
    pub about_me: String,
    pub secret: PasswordProtected<Secret>
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UserCrypto {
    pub olm_account: Encrypted<AccountPickle>,
    pub settings: Encrypted<UserSettings>,
    pub signature_verifier: SignatureVerifier
}
