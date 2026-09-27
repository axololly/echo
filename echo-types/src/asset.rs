use std::{fmt::{Debug, Display}, sync::LazyLock};

use serde::{Deserialize, Serialize};
use sqlx::postgres::{PgArgumentBuffer, PgTypeInfo, PgValueRef};

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
        buf: &mut PgArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        let hex_repr = hex::encode(self.0);

        buf.extend_from_slice(hex_repr.as_bytes());

        Ok(sqlx::encode::IsNull::No)
    }
}

impl sqlx::Decode<'_, sqlx::Postgres> for AssetID {
    fn decode(
        value: PgValueRef<'_>
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
