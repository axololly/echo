use quinn::VarInt;
use rootcause::Result;
use serde::{Serialize, de::DeserializeOwned};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct Stream {
    sender: quinn::SendStream,
    receiver: quinn::RecvStream
}

impl Stream {
    pub async fn open_bi(parent: &quinn::Connection) -> Result<Self> {
        let (sender, receiver) = parent.open_bi().await?;

        Ok(Self { sender, receiver })
    }

    pub async fn accept_bi(parent: &quinn::Connection) -> Result<Self> {
        let (sender, receiver) = parent.accept_bi().await?;

        Ok(Self { sender, receiver })
    }

    pub async fn send<T: Serialize>(&mut self, data: &T) -> Result<()> {
        let bytes = bitcode::serialize(data)?;

        self.sender.write_u64(bytes.len() as u64).await?;
        self.sender.write_all(&bytes).await?;

        Ok(())
    }

    pub async fn receive<T: DeserializeOwned>(&mut self) -> Result<T> {
        let len = self.receiver.read_u64().await?;

        let mut bytes = vec![0u8; len as usize];

        self.receiver.read_exact(&mut bytes).await?;

        let value = bitcode::deserialize(&bytes)?;

        Ok(value)
    }

    pub fn mark_done_sending(&mut self) -> Result<()> {
        self.sender.finish()?;

        Ok(())
    }

    pub fn mark_done_receiving(&mut self) -> Result<()> {
        self.receiver.stop(VarInt::from_u32(0))?;

        Ok(())
    }

    pub fn close(mut self) -> Result<()> {
        self.mark_done_sending()?;
        self.mark_done_receiving()?;

        Ok(())
    }

    pub async fn send_one<T: Serialize>(&mut self, value: &T) -> Result<()> {
        self.send(value).await?;

        self.mark_done_sending()?;

        Ok(())
    }

    pub async fn receive_one<T: DeserializeOwned>(&mut self) -> Result<T> {
        let value = self.receive().await?;

        self.mark_done_receiving()?;

        Ok(value)
    }
}
