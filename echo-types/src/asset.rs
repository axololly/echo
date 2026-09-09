use std::{fmt::{Debug, Display}, sync::LazyLock};

use blake3::OUT_LEN as ASSET_ID_SIZE;
use sqlx::{encode::IsNull, postgres::PgTypeInfo};
use serde::{Deserialize, Serialize};

pub type RawAssetID = [u8; ASSET_ID_SIZE];

#[derive(Clone, Copy, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct AssetID(RawAssetID);

impl Debug for AssetID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f
            .debug_tuple("AssetID")
            .field(&hex::encode(self.0))
            .finish()
    }
}

impl Display for AssetID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
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
    ) -> Result<IsNull, sqlx::error::BoxDynError> {
        buf.extend_from_slice(hex::encode(self.0).as_bytes());

        Ok(IsNull::No)
    }
}

impl sqlx::Decode<'_, sqlx::Postgres> for AssetID {
    fn decode(
        value: <sqlx::Postgres as sqlx::Database>::ValueRef<'_>
    ) -> Result<Self, sqlx::error::BoxDynError> {
        let bytes = value.as_bytes()?;

        let mut buf = [0; 32];

        hex::decode_to_slice(bytes, &mut buf)?;

        Ok(Self(buf))
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
