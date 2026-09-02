use serde::{Deserialize, Serialize};
use sqlx::{Decode, Encode, postgres::PgTypeInfo};
use vodozemac::megolm::MegolmMessage;

use crate::{AssetID, Encrypted, Secret, SnowflakeID};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Attachment {
    pub id: AssetID,
    pub filename: String,
    pub secret: Secret
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MessageBody {
    pub content: String
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Message {
    pub id: SnowflakeID,
    pub parent: Option<SnowflakeID>,
    pub body: Encrypted<MessageBody>,
    pub attachments: Vec<Attachment>
}

#[derive(Clone, Debug, Decode, Deserialize, Encode, Serialize)]
pub enum MessageType {
    Normal,
    Reply,
    Edit
}

impl sqlx::Type<sqlx::Postgres> for MessageType {
    fn type_info() -> PgTypeInfo {
        PgTypeInfo::with_name("\"MessageType\"")
    }
}

pub struct SqlxMegolmMessage(MegolmMessage);

impl From<SqlxMegolmMessage> for MegolmMessage {
    fn from(value: SqlxMegolmMessage) -> Self {
        value.0
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

impl sqlx::Decode<'_, sqlx::Postgres> for SqlxMegolmMessage {
    fn decode(
        value: <sqlx::Postgres as sqlx::Database>::ValueRef<'_>
    ) -> Result<Self, sqlx::error::BoxDynError> {
        let bytes = value.as_bytes()?;

        let msg = MegolmMessage::from_bytes(bytes)?;

        Ok(Self(msg))
    }
}

impl sqlx::Type<sqlx::Postgres> for SqlxMegolmMessage {
    fn type_info() -> <sqlx::Postgres as sqlx::Database>::TypeInfo {
        <Vec<u8> as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

// TODO: add Emoji and Reaction structs
