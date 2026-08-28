use std::{fmt::{Debug, Display}, sync::LazyLock};

use blake3::OUT_LEN as ASSET_ID_SIZE;
use sqlx::{Decode, Encode, postgres::PgTypeInfo};
use serde::{Deserialize, Serialize};

pub type RawAssetID = [u8; ASSET_ID_SIZE];

#[derive(Clone, Decode, Deserialize, Encode, Eq, Hash, PartialEq, Serialize)]
pub struct AssetID(String);

impl Debug for AssetID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
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

impl AssetID {
    /// Build an [`AssetID`] from a byte array.
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Self {
        let hash = blake3::hash(bytes.as_ref());

        Self(hex::encode(hash.as_bytes()))
    }
}

// TODO: needs to be added to the database in some setup function
pub static DEFAULT_PFP_ASSET_ID: LazyLock<AssetID> = LazyLock::new(|| {
    AssetID::from_bytes(include_bytes!("../../default-pfp.jpeg"))
});
