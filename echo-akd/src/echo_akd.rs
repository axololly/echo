use std::{marker::PhantomData, path::Path};

use akd::{AkdLabel, AkdValue, AzksParallelismConfig, Directory, EpochHash, HistoryParams, HistoryProof, LookupProof, WhatsAppV1Configuration, ecvrf::VRFPublicKey, storage::StorageManager};
use echo_types::{SnowflakeID, UserCrypto};
use rootcause::{Result, bail, prelude::ResultExt};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sqlx::PgPool;
use thiserror::Error;

use crate::akd_postgres::{AkdPostgres, AkdVrf};

#[derive(Clone, Deserialize, Serialize)]
pub struct LookupProved<K, V> {
    lookup_proof: LookupProof,
    epoch: u64,
    hash: [u8; 32],
    _data: PhantomData<(K, V)>
}

impl<K: Serialize, V: DeserializeOwned> LookupProved<K, V> {
    pub fn verify(
        self,
        key: &K,
        vrf_public_key: &[u8]
    ) -> Result<V> {
        let label = bitcode::serialize(key)?;

        let result = akd::client::lookup_verify::<WhatsAppV1Configuration>(
            vrf_public_key,
            self.hash,
            self.epoch,
            AkdLabel(label),
            self.lookup_proof
        );

        let value =  match result {
            Ok(verify_result) => bitcode::deserialize(&verify_result.value)?,
            Err(e) => bail!("verification error: {e:?}")
        };

       Ok(value)
    }
}

#[derive(Clone)]
pub struct KeyDirectory<K, V> {
    directory: Directory<WhatsAppV1Configuration, AkdPostgres, AkdVrf>,
    _data: PhantomData<(K, V)>
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("IO error")]
    IO,

    #[error("AKD error")]
    Akd
}

use Error as E;

impl<K, V> KeyDirectory<K, V> {
    pub async fn new(pool: PgPool, vrf_path: impl AsRef<Path>) -> Result<Self, Error> {
        let db = AkdPostgres::new(pool);
        let storage = StorageManager::new(db, None, None, None);

        let vrf = AkdVrf::from_file(vrf_path)
            .context(E::IO)?;

        let directory = Directory::new(
            storage,
            vrf,
            AzksParallelismConfig::default()
        ).await.context(E::Akd)?;

        Ok(Self {
            directory,
            _data: PhantomData
        })
    }

    pub async fn get_public_key(&mut self) -> Result<VRFPublicKey, Error> {
        self.directory
            .get_public_key()
            .await
            .context(E::Akd)
    }

    pub async fn insert(&mut self, key: &K, value: &V) -> Result<(), Error>
    where
        K: Serialize,
        V: Serialize
    {
        let key = bitcode::serialize(key).expect("failed to serialise key");
        let value = bitcode::serialize(value).expect("failed to serialise value");

        let updates = vec![
            (AkdLabel(key), AkdValue(value))
        ];

        self
            .directory
            .publish(updates)
            .await
            .context(E::Akd)?;

        Ok(())
    }

    pub async fn single_lookup(&mut self, key: &K) -> Result<LookupProved<K, V>, Error>
    where
        K: Serialize,
        V: DeserializeOwned
    {
        let key = bitcode::serialize(key).expect("failed to serialise key");

        let (lookup_proof, EpochHash(epoch, hash)) = self
            .directory
            .lookup(AkdLabel(key.clone()))
            .await
            .context(E::Akd)?;

        Ok(LookupProved {
            lookup_proof,
            epoch,
            hash,
            _data: PhantomData
        })
    }

    pub async fn history_lookup(&mut self, key: &K, limit: Option<usize>) -> Result<(HistoryProof, EpochHash), Error>
    where
        K: Serialize
    {
        let history_params = match limit {
            Some(amount) => HistoryParams::MostRecent(amount),
            None => HistoryParams::Complete
        };

        let key = bitcode::serialize(key).expect("failed to serialise key");

        let (history_proof, epoch_hash) = self
            .directory
            .key_history(
                &AkdLabel(key),
                history_params
            )
            .await
            .context(E::Akd)?;

        Ok((history_proof, epoch_hash))
    }
}

pub type EchoAkd = KeyDirectory<SnowflakeID, UserCrypto>;
pub type EchoLookupProof = LookupProved<SnowflakeID, UserCrypto>;
pub type SerdeEpochHash = (u64, [u8; 32]);
