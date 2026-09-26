use std::io;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub trait AsyncVarintReader {
    /// Read a `u64` that was written using
    /// variable-length integer encoding.
    async fn read_varint(&mut self) -> std::io::Result<u64>;
}

impl<R: AsyncReadExt + Unpin> AsyncVarintReader for R {
    async fn read_varint(&mut self) -> std::io::Result<u64> {
        let mut result: u64 = 0;
        let mut shift: u32 = 0;
        let mut byte_buf = [0u8; 1];

        loop {
            self.read_exact(&mut byte_buf).await?;

            let byte = byte_buf[0];
            let value = (byte & 0x7F) as u64;

            if shift >= 63 && value > 1 {
                return Err(io::Error::other("variable integer does not fit in a u64"));
            }

            result |= value << shift;
            shift += 7;

            if byte & 0x80 == 0 {
                break;
            }

            if shift >= 64 {
                return Err(std::io::Error::other("variable integer does not fit in a u64"));
            }
        }

        Ok(result)
    }
}

pub trait AsyncVarintWriter {
    /// Write a `u64` using variable-length integer encoding.
    async fn write_varint(&mut self, value: u64) -> std::io::Result<()>;
}

impl<W: AsyncWriteExt + Unpin> AsyncVarintWriter for W {
    async fn write_varint(&mut self, mut value: u64) -> std::io::Result<()> {
        while value > 0 {
            let mut byte = (value & 0x7F) as u8;

            value >>= 7;

            if value != 0 {
                byte |= 0x80;
            }

            self.write_all(&[byte]).await?;
        }

        Ok(())
    }
}
