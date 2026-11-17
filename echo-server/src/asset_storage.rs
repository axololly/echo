use std::{io::Result, path::PathBuf, sync::Arc};

use echo_types::AssetID;
use tokio::fs;

/// Asset storage that organises its contents on the file system.
#[derive(Clone)]
pub struct AssetStorage {
    root_dir: Arc<PathBuf>
}

impl AssetStorage {
    pub fn new(root_dir: PathBuf) -> Self {
        Self {
            root_dir: Arc::new(root_dir)
        }
    }

    /// Try to fetch an asset from storage by ID, returning `None`
    /// if it could not be found.
    pub async fn try_fetch(&self, id: AssetID) -> Result<Option<Vec<u8>>> {
        let hex = id.to_string();

        let (parent, child) = hex.split_at(2);

        let path = self
            .root_dir
            .join(parent)
            .join(child);

        let exists = fs::try_exists(&path).await?;

        if !exists {
            return Ok(None);
        }

        let data = fs::read(path).await?;

        Ok(Some(data))
    }

    /// Upload some data to asset storage and return the ID
    /// used to fetch it again.
    pub async fn upload(&self, data: impl AsRef<[u8]> + Send) -> Result<AssetID> {
        let data = data.as_ref();

        let id = AssetID::from_bytes(data);

        let hex = id.to_string();

        let (parent, child) = hex.split_at(2);

        let dir = self
            .root_dir
            .join(parent);

        fs::create_dir_all(&dir).await?;

        let path = dir.join(child);

        let exists = fs::try_exists(&path).await?;

        if !exists {
            fs::write(path, data).await?;
        }

        Ok(id)
    }

    /// Delete an asset permanently from storage by ID.
    pub async fn delete(&self, id: AssetID) -> Result<()> {
        let hex = id.to_string();

        let (parent, child) = hex.split_at(2);

        let path = self
            .root_dir
            .join(parent)
            .join(child);

        if fs::try_exists(&path).await? {
            fs::remove_file(path).await?;
        }

        Ok(())
    }
}
