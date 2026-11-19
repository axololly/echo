use std::{path::Path, sync::Arc};

use rootcause::{Result, option_ext::OptionExt};
use tokio::fs;

#[derive(Debug)]
struct FileInner {
    filename: String,
    content: Vec<u8>
}

/// A file that can be attached to a message.
#[derive(Clone, Debug)]
pub struct File(Arc<FileInner>);

impl File {
    /// Get the file's name.
    pub fn name(&self) -> &str {
        &self.0.filename
    }

    /// Get the file's contents.
    pub fn content(&self) -> &[u8] {
        &self.0.content
    }

    /// Create a [`File`] from a path on disk.
    pub async fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let filename = path
            .as_ref()
            .file_name()
            .context("no file name found")?
            .to_string_lossy()
            .to_string();

        let content = fs::read(path).await?;

        Ok(Self(Arc::new(FileInner {
            filename,
            content
        })))
    }

    /// Create a [`File`] from some bytes in memory.
    pub fn from_parts(filename: String, content: Vec<u8>) -> Self {
        Self(Arc::new(FileInner { filename, content }))
    }
}
