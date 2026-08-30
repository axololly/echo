use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{Decode, Encode, encode::IsNull, postgres::PgTypeInfo, prelude::FromRow};
use vodozemac::{Curve25519PublicKey, olm::AccountPickle};

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

#[derive(Clone, Debug, Deserialize, Eq, FromRow, PartialEq, Serialize)]
pub struct UserData {
    pub olm_account: Encrypted<AccountPickle>,
    pub settings: Encrypted<UserSettings>,
}

#[derive(Clone, Debug, Deserialize, Eq, FromRow, PartialEq, Serialize)]
pub struct UserCrypto {
    pub signature_verifier: SignatureVerifier
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OneTimeKey(Curve25519PublicKey);

impl sqlx::Decode<'_, sqlx::Postgres> for OneTimeKey {
    fn decode(value: <sqlx::Postgres as sqlx::Database>::ValueRef<'_>) -> Result<Self, sqlx::error::BoxDynError> {
        match Curve25519PublicKey::from_slice(value.as_bytes()?) {
            Ok(key) => Ok(Self(key)),
            Err(e) => Err(e.into())
        }
    }
}

impl sqlx::Encode<'_, sqlx::Postgres> for OneTimeKey {
    fn encode_by_ref(
        &self,
        buf: &mut <sqlx::Postgres as sqlx::Database>::ArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        buf.extend_from_slice(self.0.as_bytes());

        Ok(IsNull::No)
    }
}

impl sqlx::Type<sqlx::Postgres> for OneTimeKey {
    fn type_info() -> <sqlx::Postgres as sqlx::Database>::TypeInfo {
        <Vec<u8> as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

#[derive(Clone, Debug, Deserialize, FromRow, Serialize)]
pub struct FriendRequest {
    pub sender: SnowflakeID,
    pub one_time_key: OneTimeKey,
    pub sent_at: DateTime<Utc>
}
