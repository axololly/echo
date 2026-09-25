use quinn::{RecvStream, SendStream};
use rootcause::Result;
use serde::{Serialize, de::DeserializeOwned};

use crate::varint::{AsyncVarintReader, AsyncVarintWriter};

pub struct Stream {
    sender: SendStream,
    receiver: RecvStream
}

impl Stream {
    pub fn new(sender: SendStream, receiver: RecvStream) -> Self {
        Self { sender, receiver }
    }

    pub async fn send<T: Serialize>(&mut self, data: &T) -> Result<()> {
        let bytes = bitcode::serialize(data)?;

        self.sender.write_varint(bytes.len() as u64).await?;

        self.sender.write_all(&bytes).await?;

        Ok(())
    }

    pub async fn receive<T: DeserializeOwned>(&mut self) -> Result<T> {
        let len = self.receiver.read_varint().await?;
        let buf = &mut vec![0u8; len as usize];

        self.receiver.read_exact(buf).await?;

        let obj = bitcode::deserialize(buf)?;

        Ok(obj)
    }

    pub fn close(mut self) -> Result<()> {
        self.sender.finish()?;
        self.receiver.stop(0_u32.into())?;

        Ok(())
    }
}
