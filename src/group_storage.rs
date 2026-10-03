use std::{collections::{BTreeMap, HashMap}, sync::{Arc, Mutex}};

use mls_rs::{GroupStateStorage, error::IntoAnyError};
use mls_rs_core::group::{EpochRecord, GroupState};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Data about an MLS group, used in [`MyGroupStorage`].
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct GroupData {
    epochs: BTreeMap<u64, Vec<u8>>,
    state: Vec<u8>
}

/// An in-memory implementation of [`GroupStateStorage`].
#[derive(Clone, Default)]
pub struct MyGroupStorage {
    inner: Arc<Mutex<HashMap<Vec<u8>, GroupData>>>
}

impl MyGroupStorage {
    /// Serialize the group storage and then check its size.
    pub fn serialized_size(&self) -> usize {
        let inner = self.inner.lock().unwrap();

        bitcode::serialize(&*inner)
            .expect("failed to serialise")
            .len()
    }
}

#[derive(Debug)]
pub struct StorageError;

impl IntoAnyError for StorageError {}

impl GroupStateStorage for MyGroupStorage {
    type Error = StorageError;

    // Retrieves the state for a group, if it exists.
    fn state(&self, group_id: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        let data = self
            .inner
            .lock()
            .unwrap()
            .get(group_id)
            .map(|data| data.state.clone())
            .map(Zeroizing::new);

        Ok(data)
    }

    // Retrieves the state attached to an epoch within the group, if it exists.
    // This is used to fetch previous states, if necessary.
    fn epoch(
        &self,
        group_id: &[u8],
        epoch_id: u64,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        let found = self
            .inner
            .lock()
            .unwrap()
            .get(group_id)
            .and_then(|data| data.epochs.get(&epoch_id))
            .map(|state| Zeroizing::new(state.clone()));

        Ok(found)
    }

    // Update the data for a given group, inserting states for
    // new epochs and updating states for old epochs.
    fn write(
        &mut self,
        state: GroupState,
        epoch_inserts: Vec<EpochRecord>,
        epoch_updates: Vec<EpochRecord>,
    ) -> Result<(), Self::Error> {
        let mut inner = self
            .inner
            .lock()
            .unwrap();

        let data = inner
            .entry(state.id)
            .or_default();

        data.state = (*state.data).clone();

        for insert in epoch_inserts {
            data.epochs.insert(insert.id, (*insert.data).clone());
        }

        for update in epoch_updates {
            data.epochs.insert(update.id, (*update.data).clone());
        }

        Ok(())
    }

    // Find the latest epoch for a given group.
    fn max_epoch_id(&self, group_id: &[u8]) -> Result<Option<u64>, Self::Error> {
        let max = self
            .inner
            .lock()
            .unwrap()
            .get(group_id)
            .and_then(|data| data.epochs.last_key_value())
            .map(|(&max_epoch, _)| max_epoch);

        Ok(max)
    }
}
