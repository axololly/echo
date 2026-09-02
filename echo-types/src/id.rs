use std::{fmt::Display, sync::{Arc, LazyLock, Mutex, atomic::{AtomicU64, Ordering}}};

use chrono::{DateTime, Utc};
use ferroid::{define_snowflake_id, generator::{Poll, SnowflakeGenerator}, time::TimeSource};
use serde::{Deserialize, Serialize};
use sqlx::{Decode, Encode};
use thiserror::Error;

define_snowflake_id!(
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

struct UtcTimeSource;

impl TimeSource<u64> for UtcTimeSource {
    fn current_millis(&self) -> u64 {
        Utc::now().timestamp_millis() as u64
    }
}

pub struct Generator {
    machine_id: u64,
    last_timestamp: Arc<Mutex<DateTime<Utc>>>,
    next_seq_num: AtomicU64
}

#[derive(Debug, Error)]
#[error("failed to generate snowflake ID")]
pub struct SnowflakeGenerationError;

impl SnowflakeGenerator<SnowflakeID, UtcTimeSource> for Generator {
    type Err = SnowflakeGenerationError;

    fn new(machine_id: u64, _: UtcTimeSource) -> Self {
        Self {
            machine_id,
            last_timestamp: Arc::new(Mutex::new(Utc::now())),
            next_seq_num: AtomicU64::new(1)
        }
    }

    fn try_next_id(&self, mut f: impl FnMut(u64)) -> Result<SnowflakeID, Self::Err> {
        let now = Utc::now();

        let Ok(mut last) = self.last_timestamp.lock() else {
            return Err(SnowflakeGenerationError);
        };

        let delta = now - *last;

        *last = now;

        let sequence = if delta.num_milliseconds() == 0 {
            self.next_seq_num.fetch_add(1, Ordering::Relaxed)
        }
        else {
            self.next_seq_num.swap(0, Ordering::Relaxed)
        };

        let snowflake = SnowflakeID::from_components(now.timestamp() as u64, self.machine_id, sequence);

        f(snowflake.id);

        Ok(snowflake)
    }

    fn try_poll_id(&self) -> Result<Poll<SnowflakeID>, Self::Err> {
        Ok(Poll::Ready {
            id: self.try_next_id(|_| {})?
        })
    }
}

impl Generator {
    pub fn next(&self) -> SnowflakeID {
        self.try_next_id(|_| ()).expect("failed to generate new ID")
    }
}

pub static SNOWFLAKE_GEN: LazyLock<Generator> = LazyLock::new(|| {
    Generator::new(1, UtcTimeSource) // TODO: change the machine ID
});
