use std::fmt::{Debug, Display};

use chrono::{DateTime, Utc};
use rootcause::{bail, prelude::ResultExt};
use serde::{Deserialize, Serialize};
use sqlx::prelude::FromRow;

use crate::{AssetID, SnowflakeID};

/// A member of a group chat, packaging
/// their user ID and when they joined.
#[derive(Clone, Copy, Debug, Deserialize, Eq, FromRow, PartialEq, Serialize)]
pub struct GroupMember {
    pub user_id: SnowflakeID,
    pub joined_at: DateTime<Utc>
}

/// An Echo group chat.
///
/// The members list is sorted by join time
/// with oldest members at the beginning
/// and newest members at the end.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Group {
    pub id: SnowflakeID,
    pub name: String,
    pub members: Vec<GroupMember>,
    pub avatar: Option<AssetID>,
    pub created_at: DateTime<Utc>,
    pub invite_code: GroupInvite
}

impl Group {
    pub fn owner(&self) -> &GroupMember {
        &self.members[0]
    }
}

pub const GROUP_INVITE_CODE_LEN: usize = 8;

/// An invite code for a group, specifically designed
/// to be `Copy`.
#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
pub struct GroupInvite([u8; GROUP_INVITE_CODE_LEN]);

static VALID_INVITE_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

impl GroupInvite {
    /// Generate a random [`GroupInvite`].
    pub fn random() -> Self {
        let len = VALID_INVITE_CHARS.len() as u8;

        let mut data = [0; GROUP_INVITE_CODE_LEN];

        let iter = rand::random_iter::<u8>()
            .take(GROUP_INVITE_CODE_LEN)
            .map(|i| i % len)
            .map(|idx| VALID_INVITE_CHARS[idx as usize])
            .enumerate();

        for (idx, byte) in iter {
            data[idx] = byte;
        }

        Self(data)
    }
}

impl<'a> From<&'a GroupInvite> for &'a str {
    fn from(value: &'a GroupInvite) -> Self {
        str::from_utf8(&value.0)
            .attach("group invite unexpectedly contained invalid UTF-8")
            .unwrap()
    }
}

impl Debug for GroupInvite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let raw: &str = self.into();

        f
            .debug_struct("GroupInvite")
            .field("code", &raw)
            .finish()
    }
}

impl Display for GroupInvite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let raw: &str = self.into();

        write!(f, "{raw}")
    }
}

impl sqlx::Encode<'_, sqlx::Postgres> for GroupInvite {
    fn encode_by_ref(
        &self,
        buf: &mut <sqlx::Postgres as sqlx::Database>::ArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError>
    {
        buf.extend_from_slice(&self.0);

        Ok(sqlx::encode::IsNull::No)
    }
}

impl sqlx::Decode<'_, sqlx::Postgres> for GroupInvite {
    fn decode(
        value: <sqlx::Postgres as sqlx::Database>::ValueRef<'_>
    ) -> Result<Self, sqlx::error::BoxDynError> {
        let s = value.as_str()?;

        if s.len() != GROUP_INVITE_CODE_LEN {
            bail!("invalid length for invite code (expected {GROUP_INVITE_CODE_LEN}, got {})", s.len());
        }

        for byte in s.as_bytes() {
            let valid = byte.is_ascii_digit() || (
                byte.is_ascii_alphabetic() && byte.is_ascii_uppercase()
            );

            if !valid {
                bail!("invalid byte found in invite code");
            }
        }

        let data: [u8; _] = s
            .as_bytes()
            .try_into()?;

        Ok(Self(data))
    }
}

impl sqlx::Type<sqlx::Postgres> for GroupInvite {
    fn type_info() -> <sqlx::Postgres as sqlx::Database>::TypeInfo {
        <String as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

/// A member who was banned from a group,
/// and the reason why, if given.
#[derive(Clone, Deserialize, FromRow, Serialize)]
pub struct BannedMember {
    pub member_id: SnowflakeID,
    pub banned_at: DateTime<Utc>,
    pub reason: Option<String>
}
