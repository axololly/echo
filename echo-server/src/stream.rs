use quinn::VarInt;
use rootcause::{Result, bail, prelude::ResultExt};
use serde::{Serialize, de::DeserializeOwned};
use tokio::io::AsyncWriteExt;

use crate::{error::{RouteError, RouteResult}, varint::{AsyncVarintReader, AsyncVarintWriter}};

pub const DATA_TOO_LARGE: VarInt = VarInt::from_u32(100);

/// A wrapper over a QUIC stream that allows for
/// sending and receiving complex data structures.
///
/// Data is sent and received as length-prefixed
/// linear streams of bytes that are deserialised
/// and serialised respectively into expected types.
pub struct Stream {
    sender: quinn::SendStream,
    receiver: quinn::RecvStream
}

impl Stream {
    /// Open a bidirectional stream using the given QUIC connection.
    pub async fn open_bi(parent: &quinn::Connection) -> Result<Self> {
        let (sender, receiver) = parent.open_bi().await?;

        Ok(Self { sender, receiver })
    }

    /// Accept a bidirectional stream using the given QUIC connection.
    pub async fn accept_bi(parent: &quinn::Connection) -> Result<Self> {
        let (sender, receiver) = parent.accept_bi().await?;

        Ok(Self { sender, receiver })
    }

    /// Send some data over this [`Stream`].
    pub async fn send<T: Serialize>(&mut self, data: &T) -> RouteResult<()> {
        let bytes = bitcode::serialize(data)
            .context(RouteError::Transport)
            .attach(format!("while serialising data of type {}", std::any::type_name::<T>()))?;

        self
            .sender
            .write_varint(bytes.len() as u64)
            .await
            .context(RouteError::Transport)
            .attach("while writing length")?;

        self
            .sender
            .flush()
            .await
            .context(RouteError::Transport)
            .attach("while flushing length")?;

        self
            .sender
            .write_all(&bytes)
            .await
            .context(RouteError::Transport)
            .attach("while writing main data")?;

        Ok(())
    }

    /// Receive some data over this [`Stream`].
    pub async fn receive<T: DeserializeOwned>(&mut self) -> RouteResult<T> {
        let len = self
            .receiver
            .read_varint()
            .await
            .context(RouteError::Transport)
            .attach("while receiving length")?;

        let mut bytes = vec![0u8; len as usize];

        self
            .receiver
            .read_exact(&mut bytes)
            .await
            .context(RouteError::Transport)
            .attach("while receiving main content")?;

        let value = bitcode::deserialize(&bytes)
            .context(RouteError::InvalidData)
            .attach(format!("while deserialising data to type {}", std::any::type_name::<T>()))?;

        Ok(value)
    }

    /// Receive some data over this [`Stream`], but close
    /// the receiver if more data than `cap` is sent.
    pub async fn receive_capped<T: DeserializeOwned>(&mut self, cap: u64) -> RouteResult<T> {
        let len = self
            .receiver
            .read_varint()
            .await
            .context(RouteError::Transport)
            .attach("while receiving length")?;

        if len > cap {
            println!("cap exceeded! {len} (cap: {cap})");

            let _ = self.receiver.stop(DATA_TOO_LARGE);

            bail!(RouteError::DataTooLarge(cap));
        }

        let mut bytes = vec![0u8; len as usize];

        self
            .receiver
            .read_exact(&mut bytes)
            .await
            .context(RouteError::Transport)
            .attach("while receiving main content")?;

        let value = bitcode::deserialize(&bytes)
            .context(RouteError::InvalidData)
            .attach(format!("while deserialising data to type {}", std::any::type_name::<T>()))?;

        Ok(value)
    }

    /// Mark the stream as done sending and done receiving,
    /// before dropping the sender and receiver.
    pub fn close(mut self) -> Result<()> {
        self.sender.finish()?;
        self.receiver.stop(VarInt::from_u32(0))?;

        Ok(())
    }
}
