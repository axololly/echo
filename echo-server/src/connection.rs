use quinn::VarInt;
use rootcause::{Result, prelude::ResultExt};
use serde::{Serialize, de::DeserializeOwned};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::{RouteError, RouteResult};

/// A wrapper over a QUIC stream that allows for
/// sending and receiving complex data structures.
///
/// Data is sent and received as length-prefixed
/// linear streams of bytes that are deserialised
/// and serialised respectively into expected types.
pub struct Connection {
    sender: quinn::SendStream,
    receiver: quinn::RecvStream
}

impl Connection {
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

    /// Send some data over this [`Connection`].
    pub async fn send<T: Serialize>(&mut self, data: &T) -> RouteResult<()> {
        let bytes = bitcode::serialize(data)
            .context(RouteError::Transport)
            .attach(format!("while serialising data of type {}", std::any::type_name::<T>()))?;

        self
            .sender
            .write_u64(bytes.len() as u64)
            .await
            .context(RouteError::Transport)
            .attach("while writing length")?;

        self
            .sender
            .write_all(&bytes)
            .await
            .context(RouteError::Transport)
            .attach("while writing main data")?;

        Ok(())
    }

    /// Receive some data over this [`Connection`].
    pub async fn receive<T: DeserializeOwned>(&mut self) -> RouteResult<T> {
        let len = self
            .receiver
            .read_u64()
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
            .context(RouteError::InvalidData)?;

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
