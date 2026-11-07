use rootcause::prelude::ResultExt;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgTypeInfo;
use vodozemac::{Curve25519PublicKey, megolm::MegolmMessage};

/// A [`sqlx`]-compliant wrapper around [`vodozemac`]'s [`Curve25519PublicKey`].
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OlmPublicKey(Curve25519PublicKey);

impl From<Curve25519PublicKey> for OlmPublicKey {
    fn from(value: Curve25519PublicKey) -> Self {
        Self(value)
    }
}

impl From<OlmPublicKey> for Curve25519PublicKey {
    fn from(value: OlmPublicKey) -> Self {
        value.0
    }
}

impl sqlx::Decode<'_, sqlx::Postgres> for OlmPublicKey {
    fn decode(
        value: <sqlx::Postgres as sqlx::Database>::ValueRef<'_>
    ) -> Result<Self, sqlx::error::BoxDynError> {
        let bytes = value.as_bytes()?;

        let key = Curve25519PublicKey::from_slice(bytes)?;

        Ok(Self(key))
    }
}

impl sqlx::Encode<'_, sqlx::Postgres> for OlmPublicKey {
    fn encode_by_ref(
        &self,
        buf: &mut <sqlx::Postgres as sqlx::Database>::ArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        buf.extend_from_slice(&self.0.to_bytes());

        Ok(sqlx::encode::IsNull::No)
    }
}

impl sqlx::Type<sqlx::Postgres> for OlmPublicKey {
    fn type_info() -> PgTypeInfo {
        <[u8; 32]>::type_info()
    }
}

/// A [`sqlx`]-compliant wrapper around [`vodozemac`]'s [`OlmMessage`].
#[derive(Clone, Deserialize, Serialize)]
pub struct SqlxMegolmMessage(MegolmMessage);

impl From<MegolmMessage> for SqlxMegolmMessage {
    fn from(value: MegolmMessage) -> Self {
        Self(value)
    }
}

impl From<SqlxMegolmMessage> for MegolmMessage {
    fn from(value: SqlxMegolmMessage) -> Self {
        value.0
    }
}

impl sqlx::Decode<'_, sqlx::Postgres> for SqlxMegolmMessage {
    fn decode(
        value: <sqlx::Postgres as sqlx::Database>::ValueRef<'_>
    ) -> Result<Self, sqlx::error::BoxDynError> {
        let bytes = value.as_bytes()?;

        let msg = MegolmMessage::from_bytes(bytes)
            .context("failed to decode olm message")?;

        Ok(Self(msg))
    }
}

impl sqlx::Encode<'_, sqlx::Postgres> for SqlxMegolmMessage {
    fn encode_by_ref(
        &self,
        buf: &mut <sqlx::Postgres as sqlx::Database>::ArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        buf.extend_from_slice(&self.0.to_bytes());

        Ok(sqlx::encode::IsNull::No)
    }
}

impl sqlx::Type<sqlx::Postgres> for SqlxMegolmMessage {
    fn type_info() -> PgTypeInfo {
        <Vec::<u8> as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}
