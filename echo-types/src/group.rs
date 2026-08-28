use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::prelude::FromRow;

use crate::{AssetID, SnowflakeID};

#[derive(Clone, Copy, Debug, Deserialize, FromRow, Serialize)]
pub struct GroupMember {
    pub user_id: SnowflakeID,
    pub joined_at: DateTime<Utc>
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Group {
    pub id: SnowflakeID,
    pub name: String,
    pub avatar: AssetID,
    pub members: Vec<GroupMember>
}

impl Group {
    pub fn owner(&self) -> GroupMember {
        self.members[0]
    }
}
