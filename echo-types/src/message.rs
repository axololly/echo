use serde::{Deserialize, Serialize};

use crate::AssetID;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Message {
    pub content: String,
    pub attachments: Vec<AssetID>
}
