use std::{fmt::{Debug, Display}, sync::LazyLock};

use serde::{Deserialize, Serialize};
use sqlx::{Decode, Encode, postgres::PgTypeInfo, prelude::FromRow};

use crate::{Encrypted, PasswordProtected, Secret, SignatureVerifier, SnowflakeID};

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

/// A unique ID obtained through hashing the content of
/// an asset, that being any binary data stored on the server.
#[derive(Clone, Copy, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct AssetID([u8; 32]);

impl Debug for AssetID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AssetID({})", hex::encode(self.0))
    }
}

impl Display for AssetID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl sqlx::Type<sqlx::Postgres> for AssetID {
    fn type_info() -> PgTypeInfo {
        <String as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

impl sqlx::Encode<'_, sqlx::Postgres> for AssetID {
    fn encode_by_ref(
        &self,
        buf: &mut <sqlx::Postgres as sqlx::Database>::ArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        let hex_repr = hex::encode(self.0);

        buf.extend_from_slice(hex_repr.as_bytes());

        Ok(sqlx::encode::IsNull::No)
    }
}

impl sqlx::Decode<'_, sqlx::Postgres> for AssetID {
    fn decode(
        value: <sqlx::Postgres as sqlx::Database>::ValueRef<'_>
    ) -> Result<Self, sqlx::error::BoxDynError> {
        let bytes = value.as_bytes()?;

        let out = &mut [0; 32];

        hex::decode_to_slice(bytes, out)?;

        Ok(Self(*out))
    }
}

impl AssetID {
    /// Build an [`AssetID`] from a byte array.
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Self {
        let hash = blake3::hash(bytes.as_ref());

        Self(*hash.as_bytes())
    }
}

// TODO: needs to be added to the database in some setup function
pub static DEFAULT_PFP_ASSET_ID: LazyLock<AssetID> = LazyLock::new(|| {
    AssetID::from_bytes(include_bytes!("../../default-pfp.jpeg"))
});

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
    pub signature_verifier: SignatureVerifier
}
