use std::{fmt::Display, sync::{Arc, LazyLock, Mutex, atomic::{AtomicU64, Ordering}}};

use chrono::{DateTime, Utc};
use ferroid::define_snowflake_id;
use serde::{Deserialize, Serialize};
use sqlx::{Decode, Encode};

define_snowflake_id!(
    /// A snowflake ID used for uniquely identifying data
    /// and for organising data by time.
    #[derive(Deserialize, Serialize)]
    SnowflakeID, u64,
    reserved: 1,
    timestamp: 41,
    machine_id: 10,
    sequence: 12
);

impl Display for SnowflakeID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.id)
    }
}

impl Encode<'_, sqlx::Postgres> for SnowflakeID {
    fn encode_by_ref(
        &self,
        buf: &mut <sqlx::Postgres as sqlx::Database>::ArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError>
    {
        buf.extend_from_slice(&self.id.to_be_bytes());

        Ok(sqlx::encode::IsNull::No)
    }
}

impl Decode<'_, sqlx::Postgres> for SnowflakeID {
    fn decode(value: <sqlx::Postgres as sqlx::Database>::ValueRef<'_>) -> Result<Self, sqlx::error::BoxDynError> {
        let bytes: [u8; 8] = value.as_bytes()?.try_into()?;

        Ok(Self {
            id: u64::from_be_bytes(bytes)
        })
    }
}

impl sqlx::Type<sqlx::Postgres> for SnowflakeID {
    fn type_info() -> <sqlx::Postgres as sqlx::Database>::TypeInfo {
        <i64 as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

/// Echo's snowflake ID generator.
///
/// Sequence numbers are used to differentiate between
/// snowflake IDs created within the same millisecond.
pub struct SnowflakeGenerator {
    machine_id: u64,
    last_timestamp: Arc<Mutex<DateTime<Utc>>>,
    next_seq_num: AtomicU64
}

impl SnowflakeGenerator {
    /// Create a new snowflake generator with a given machine ID.
    ///
    /// Machine IDs are used to differentiate between multiple
    /// instances running concurrently.
    pub fn new(machine_id: u64) -> Self {
        Self {
            machine_id,
            last_timestamp: Arc::new(Mutex::new(Utc::now())),
            next_seq_num: AtomicU64::new(0)
        }
    }

    /// Generate the next [`SnowflakeID`].
    pub fn next(&self) -> SnowflakeID {
        let now = Utc::now();

        let mut last = match self.last_timestamp.lock() {
            Ok(lock) => lock,
            Err(e) => {
                self.last_timestamp.clear_poison();

                e.into_inner()
            }
        };

        let delta = now - *last;

        *last = now;

        let sequence = if delta.num_milliseconds() == 0 {
            self.next_seq_num.fetch_add(1, Ordering::Relaxed)
        }
        else {
            self.next_seq_num.swap(0, Ordering::Relaxed)
        };

        SnowflakeID::from_components(
            now.timestamp() as u64,
            self.machine_id,
            sequence
        )
    }
}

/// A project-wide snowflake ID generator.
pub static SNOWFLAKE_GEN: LazyLock<SnowflakeGenerator> = LazyLock::new(|| {
    // TODO: change the machine ID to something like the process ID
    SnowflakeGenerator::new(1)
});
