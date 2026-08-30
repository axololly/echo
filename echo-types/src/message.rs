use serde::{Deserialize, Serialize};

use crate::{AssetID, Secret};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Attachment {
    id: AssetID,
    filename: String,
    secret: Secret
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Message {
    pub content: String,
    pub attachments: Vec<Attachment>
}
