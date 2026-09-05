use std::{collections::HashMap, path::Path};

use akd::{AkdLabel, AkdValue, Azks, AzksValue, NodeLabel, append_only_zks::DEFAULT_AZKS_KEY, ecvrf::{VRFKeyStorage, VrfError}, errors::StorageError, storage::{Database, DbSetState, Storable, types::{DbRecord, KeyData, StorageType, ValueState, ValueStateKey, ValueStateRetrievalFlag}}, tree_node::{TreeNode, TreeNodeType, TreeNodeWithPreviousValue}};
use async_trait::async_trait;
use sqlx::{AssertSqlSafe, PgConnection, PgExecutor, PgPool};

use crate::*;

#[derive(sqlx::Type)]
#[sqlx(type_name = "\"NodeType\"")]
enum NodeType {
    Leaf,
    Root,
    Interior
}

impl From<TreeNodeType> for NodeType {
    fn from(value: TreeNodeType) -> Self {
        match value {
            TreeNodeType::Leaf => Self::Leaf,
            TreeNodeType::Root => Self::Root,
            TreeNodeType::Interior => Self::Interior
        }
    }
}

impl From<NodeType> for TreeNodeType {
    fn from(value: NodeType) -> Self {
        match value {
            NodeType::Leaf => TreeNodeType::Leaf,
            NodeType::Root => TreeNodeType::Root,
            NodeType::Interior => TreeNodeType::Interior
        }
    }
}

#[derive(Clone)]
pub struct AkdPostgres {
    pool: PgPool
}

impl AkdPostgres {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

type StorageResult<T> = Result<T, StorageError>;

fn label_to_bytes(label: &NodeLabel) -> &[u8] {
    &label.label_val[.. (label.label_len / 8) as usize]
}

fn bytes_to_label(bytes: Vec<u8>) -> NodeLabel {
    let mut buf = [0; 32];

    let len = bytes.len().min(32);

    buf[.. len].copy_from_slice(&bytes[.. len]);

    NodeLabel {
        label_len: bytes.len() as u32,
        label_val: buf
    }
}

async fn store_record(exec: impl PgExecutor<'_>, record: DbRecord) -> StorageResult<()> {
    match record {
        DbRecord::Azks(azks) => {
            let stmt = "
                INSERT INTO akd_azks (id, latest_epoch, num_nodes)
                VALUES ($1, $2, $3)
                ON CONFLICT (id)
                DO UPDATE SET
                    latest_epoch = EXCLUDED.latest_epoch,
                    num_nodes = EXCLUDED.num_nodes
            ";

            execute!(
                exec,
                stmt,
                DEFAULT_AZKS_KEY as i16,
                azks.latest_epoch as i64,
                azks.num_nodes as i64
            );
        },
        DbRecord::TreeNode(tree_node) => {
            let stmt = "
                INSERT INTO akd_tree_nodes (
                    label,
                    last_epoch,
                    min_descendant_epoch,
                    parent,
                    node_type,
                    left_child,
                    right_child,
                    hash
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                ON CONFLICT (label, last_epoch) DO UPDATE SET
                    min_descendant_epoch = EXCLUDED.min_descendant_epoch,
                    parent = EXCLUDED.parent,
                    node_type = EXCLUDED.node_type,
                    left_child = EXCLUDED.left_child,
                    right_child = EXCLUDED.right_child,
                    hash = EXCLUDED.hash
            ";

            let node = &tree_node.latest_node;

            execute!(
                exec,
                stmt,
                label_to_bytes(&node.label),
                node.last_epoch as i64,
                node.min_descendant_epoch as i64,
                label_to_bytes(&node.parent),
                NodeType::from(node.node_type),
                node.left_child.as_ref().map(label_to_bytes),
                node.right_child.as_ref().map(label_to_bytes),
                node.hash.0
            );
        },
        DbRecord::ValueState(state) => {
            let stmt = "
                INSERT INTO akd_value_states (
                    username,
                    epoch,
                    label,
                    version,
                    value
                ) VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT DO NOTHING
            ";

            execute!(
                exec,
                stmt,
                state.username.0,
                state.epoch as i64,
                label_to_bytes(&state.label),
                state.version as i64,
                state.value.0
            );
        }
    }

    Ok(())
}

#[derive(sqlx::FromRow)]
struct TreeNodeEntry {
    label: Vec<u8>,
    last_epoch: i64,
    min_descendant_epoch: i64,
    node_type: NodeType,
    parent: Vec<u8>,
    left_child: Option<Vec<u8>>,
    right_child: Option<Vec<u8>>,
    hash: [u8; 32]
}

impl From<TreeNodeEntry> for TreeNode {
    fn from(value: TreeNodeEntry) -> TreeNode {
        let TreeNodeEntry {
            label,
            last_epoch,
            min_descendant_epoch,
            node_type,
            parent,
            left_child,
            right_child,
            hash
        } = value;

        TreeNode {
            label: bytes_to_label(label),
            last_epoch: last_epoch as u64,
            min_descendant_epoch: min_descendant_epoch as u64,
            node_type: TreeNodeType::from(node_type),
            parent: bytes_to_label(parent),
            left_child: left_child.map(bytes_to_label),
            right_child: right_child.map(bytes_to_label),
            hash: AzksValue(hash)
        }
    }
}

async fn get_record<St: Storable>(conn: &mut PgConnection, key: &St::StorageKey) -> StorageResult<DbRecord> {
    match St::data_type() {
        StorageType::Azks => {
            let (latest_epoch, num_nodes): (i64, i64) = fetch_one_as!(
                conn,
                "SELECT latest_epoch, num_nodes FROM akd_azks WHERE id = $1",
                DEFAULT_AZKS_KEY as i16
            );

            let record = DbRecord::Azks(Azks {
                latest_epoch: latest_epoch as u64,
                num_nodes: num_nodes as u64
            });

            Ok(record)
        },

        StorageType::TreeNode => {
            let binary_key = St::get_full_binary_key_id(key);
            let node_key = TreeNodeWithPreviousValue::key_from_full_binary(&binary_key)
                .map_err(|raw| StorageError::Other(format!("failed to convert storable key {raw:?} to node key")))?;

            let node_label = node_key.0;

            let stmt = "
                SELECT
                    label,
                    last_epoch,
                    min_descendant_epoch,
                    node_type,
                    parent,
                    left_child,
                    right_child,
                    hash
                FROM akd_tree_nodes
                WHERE label = $1
                ORDER BY last_epoch DESC
                LIMIT 2
            ";

            let mut nodes: Vec<TreeNodeEntry> = fetch_all_as!(
                &mut *conn,
                stmt,
                label_to_bytes(&node_label)
            );

            if nodes.is_empty() {
                return Err(StorageError::NotFound("cannot find current tree node".to_string()));
            }

            let latest_node = TreeNode::from(nodes.remove(0));

            let previous_node = if !nodes.is_empty() {
                Some(TreeNode::from(nodes.remove(0)))
            }
            else {
                None
            };

            let node = TreeNodeWithPreviousValue {
                label: node_label,
                latest_node,
                previous_node
            };

            Ok(DbRecord::TreeNode(node))
        },

        StorageType::ValueState => {
            let binary_key = St::get_full_binary_key_id(key);
            let ValueStateKey(username, version) = ValueState::key_from_full_binary(&binary_key)
                .map_err(|raw| StorageError::Other(format!("failed to convert storable key {raw:?} to value state key")))?;

            let (
                label,
                epoch,
                value
            ): (Vec<u8>, i64, Vec<u8>) = fetch_one_as!(
                conn,
                "SELECT label, epoch, value FROM akd_value_states WHERE username = $1 AND version = $2",
                &username,
                version as i64
            );

            let state = ValueState {
                value: AkdValue(value),
                version,
                label: bytes_to_label(label),
                epoch: epoch as u64,
                username: AkdLabel(username)
            };

            Ok(DbRecord::ValueState(state))
        }
    }
}

#[async_trait]
impl Database for AkdPostgres {
    async fn set(&self, record: DbRecord) -> StorageResult<()> {
        store_record(&self.pool, record).await
    }

    async fn batch_set(&self, records: Vec<DbRecord>, _: DbSetState) -> StorageResult<()> {
        let mut tx = self.pool.begin().await
            .map_err(|e| StorageError::Transaction(format!("{e:?}")))?;

        for record in records {
            store_record(&mut *tx, record).await?;
        }

        tx.commit().await
            .map_err(|e| StorageError::Transaction(format!("{e:?}")))?;

        Ok(())
    }

    async fn get<St: Storable>(&self, key: &St::StorageKey) -> StorageResult<DbRecord> {
        let mut conn = self.pool.acquire().await
            .map_err(|e| StorageError::Connection(format!("{e:?}")))?;

        get_record::<St>(&mut conn, key).await
    }

    async fn batch_get<St: Storable>(&self, keys: &[St::StorageKey]) -> StorageResult<Vec<DbRecord>> {
        let mut conn = self.pool.acquire().await
            .map_err(|e| StorageError::Connection(format!("{e:?}")))?;

        let mut records = Vec::with_capacity(keys.len());

        for key in keys {
            match get_record::<St>(&mut conn, key).await {
                Ok(record) => {
                    records.push(record);
                },
                Err(StorageError::NotFound(_)) => {},
                Err(e) => return Err(e)
            }
        }

        Ok(records)
    }

    async fn get_user_data(&self, username: &AkdLabel) -> StorageResult<KeyData> {
        let stmt = "
            SELECT username, epoch, label, version, value
            FROM akd_value_states
            WHERE username = $1
            ORDER BY epoch DESC
        ";

        let results: Vec<(
            Vec<u8>,
            i64,
            Vec<u8>,
            i64,
            Vec<u8>
        )> = fetch_all_as!(&self.pool, stmt, username.as_slice());

        let states = results
            .into_iter()
            .map(|(username, epoch, label, version, value)| ValueState {
                username: AkdLabel(username),
                epoch: epoch as u64,
                label: bytes_to_label(label),
                version: version as u64,
                value: AkdValue(value)
            })
            .collect();

        Ok(KeyData { states })
    }

    async fn get_user_state(&self, username: &AkdLabel, flag: ValueStateRetrievalFlag) -> StorageResult<ValueState> {
        let ext_query = match flag {
            ValueStateRetrievalFlag::MaxEpoch => "ORDER BY epoch DESC LIMIT 1",
            ValueStateRetrievalFlag::MinEpoch => "ORDER BY epoch ASC LIMIT 1",

            ValueStateRetrievalFlag::LeqEpoch(epoch) => &format!("AND epoch <= {epoch}"),
            ValueStateRetrievalFlag::SpecificEpoch(epoch) => &format!("AND epoch = {epoch}"),
            ValueStateRetrievalFlag::SpecificVersion(version) => &format!("AND version = {version}")
        };

        let stmt = format!("
            SELECT username, epoch, label, version, value
            FROM akd_value_states
            WHERE username = $1
            {ext_query}
        ");

        let (username, epoch, label, version, value): (
            Vec<u8>,
            i64,
            Vec<u8>,
            i64,
            Vec<u8>
        ) = fetch_one_as!(&self.pool, AssertSqlSafe(stmt), username.as_slice());

        let state = ValueState {
            username: AkdLabel(username),
            epoch: epoch as u64,
            label: bytes_to_label(label),
            version: version as u64,
            value: AkdValue(value)
        };

        Ok(state)
    }

    async fn get_user_state_versions(&self, usernames: &[AkdLabel], flag: ValueStateRetrievalFlag) -> StorageResult<HashMap<AkdLabel, (u64, AkdValue)>> {
        let ext_query = match flag {
            ValueStateRetrievalFlag::MaxEpoch => "ORDER BY epoch DESC LIMIT 1",
            ValueStateRetrievalFlag::MinEpoch => "ORDER BY epoch ASC LIMIT 1",

            ValueStateRetrievalFlag::LeqEpoch(epoch) => &format!("WHERE epoch <= {epoch}"),
            ValueStateRetrievalFlag::SpecificEpoch(epoch) => &format!("WHERE epoch = {epoch}"),
            ValueStateRetrievalFlag::SpecificVersion(version) => &format!("WHERE version = {version}")
        };

        let stmt = format!("
            SELECT version, value
            FROM akd_value_states
            {ext_query}
        ");

        let mut results = HashMap::new();

        for username in usernames {
            let row: Option<(i64, Vec<u8>)> = fetch_opt_as!(
                &self.pool,
                AssertSqlSafe(stmt.as_str()),
                username.as_slice()
            );

            if let Some((version, value)) = row {
                results.insert(username.clone(), (version as u64, AkdValue(value)));
            }
        }

        Ok(results)
    }
}

#[derive(Clone)]
pub struct AkdVrf {
    bytes: Vec<u8>
}

impl AkdVrf {
    pub fn from_file(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let bytes = std::fs::read(path)?;

        Ok(Self { bytes })
    }
}

#[async_trait]
impl VRFKeyStorage for AkdVrf {
    async fn retrieve(&self) -> Result<Vec<u8>, VrfError> {
        Ok(self.bytes.clone())
    }
}
