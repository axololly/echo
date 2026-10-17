use std::{fmt::{Debug, Display}, sync::{Arc, LazyLock, Mutex, atomic::{AtomicI64, Ordering}}};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A snowflake ID used for uniquely identifying data
/// and for organising data by time.
#[derive(Clone, Copy, Deserialize, Eq, Hash, PartialEq, PartialOrd, Ord, Serialize, sqlx::Type)]
#[sqlx(transparent)]
pub struct SnowflakeID {
    id: i64
}

const TIMESTAMP_BITS: usize = 41;
const MACHINE_ID_BITS: usize = 10;
const SEQUENCE_NUM_BITS: usize = 12;

impl SnowflakeID {
    pub const MAX: Self = Self {
        id: i64::MAX
    };

    /// Make a snowflake ID from raw components.
    pub const fn from_components(
        timestamp: i64,
        machine_id: i64,
        sequence_num: i64
    ) -> Self {
        assert!(timestamp < 1 << TIMESTAMP_BITS, "timestamp is too large for snowflake");
        assert!(machine_id < 1 << MACHINE_ID_BITS, "machine ID is too large for snowflake");
        assert!(sequence_num < 1 << SEQUENCE_NUM_BITS, "sequence number too large for snowflake");

        let id = timestamp << (MACHINE_ID_BITS + SEQUENCE_NUM_BITS)
            | machine_id << SEQUENCE_NUM_BITS
            | sequence_num;

        Self { id }
    }
}

impl Debug for SnowflakeID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.id)
    }
}

impl Display for SnowflakeID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.id)
    }
}

/// Echo's snowflake ID generator.
///
/// Sequence numbers are used to differentiate between
/// snowflake IDs created within the same millisecond.
pub struct SnowflakeGenerator {
    machine_id: i64,
    last_timestamp: Arc<Mutex<DateTime<Utc>>>,
    next_seq_num: AtomicI64
}

impl SnowflakeGenerator {
    /// Create a new snowflake generator with a given machine ID.
    ///
    /// Machine IDs are used to differentiate between multiple
    /// instances running concurrently.
    pub fn new(machine_id: i64) -> Self {
        Self {
            machine_id,
            last_timestamp: Arc::new(Mutex::new(Utc::now())),
            next_seq_num: AtomicI64::new(0)
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
            now.timestamp(),
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
