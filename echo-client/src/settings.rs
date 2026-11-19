use echo_types::SnowflakeID;
use serde::{Deserialize, Serialize};

/// The client-side settings a user has on their account.
///
/// These are stored encrypted on the server and fetched
/// when necessary.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserSettings {
    /// How long in seconds after going inactive
    /// before a user is logged out.
    pub logout_after: u64,

    /// Whether or not to send typing indicators
    /// to the server.
    pub enable_typing_indicators: bool,

    /// Whether or not to send read receipts to
    /// the server.
    pub enable_read_receipts: bool,

    /// Who to automatically reject future friend
    /// requests from.
    pub ignore_future_requests_from: Vec<SnowflakeID>
}
