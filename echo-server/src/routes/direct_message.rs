use echo_types::SnowflakeID;
use serde::{Deserialize, Serialize};

use crate::route;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SendDirectMessageData {
    pub conversation_id: SnowflakeID
}
