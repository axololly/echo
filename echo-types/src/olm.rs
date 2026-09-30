use serde::{Deserialize, Serialize};
use sqlx::postgres::PgTypeInfo;
use vodozemac::{Curve25519PublicKey, olm::PreKeyMessage};

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

/// A [`sqlx`]-compliant wrapper around [`vodozemac`]'s [`PreKeyMessage`].
#[derive(Clone, Deserialize, Serialize)]
pub struct OlmPreKeyMessage(PreKeyMessage);

impl From<PreKeyMessage> for OlmPreKeyMessage {
    fn from(value: PreKeyMessage) -> Self {
        Self(value)
    }
}

impl From<OlmPreKeyMessage> for PreKeyMessage {
    fn from(value: OlmPreKeyMessage) -> Self {
        value.0
    }
}

impl sqlx::Decode<'_, sqlx::Postgres> for OlmPreKeyMessage {
    fn decode(
        value: <sqlx::Postgres as sqlx::Database>::ValueRef<'_>
    ) -> Result<Self, sqlx::error::BoxDynError> {
        let bytes = value.as_bytes()?;

        let msg = PreKeyMessage::from_bytes(bytes)?;

        Ok(Self(msg))
    }
}

impl sqlx::Encode<'_, sqlx::Postgres> for OlmPreKeyMessage {
    fn encode_by_ref(
        &self,
        buf: &mut <sqlx::Postgres as sqlx::Database>::ArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        buf.extend_from_slice(&self.0.to_bytes());

        Ok(sqlx::encode::IsNull::No)
    }
}

impl sqlx::Type<sqlx::Postgres> for OlmPreKeyMessage {
    fn type_info() -> PgTypeInfo {
        <Vec::<u8> as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}
