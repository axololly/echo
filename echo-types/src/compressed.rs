use std::borrow::Cow;

use serde::{Deserialize, Serialize, de::{DeserializeOwned, Visitor}};
use zstd::{bulk::{compress, decompress}, decompressed_size};

/// Data that has its output compressed after serialisation.
///
/// The algorithm of choice is Zstd.
#[repr(transparent)]
pub struct Compressed<T> {
    value: T
}

impl<T> Compressed<T> {
    /// Compress a value on demand.
    pub fn new(value: T) -> Self {
        Self { value }
    }

    /// Unpack the internal value.
    pub fn decompress(self) -> T {
        self.value
    }
}

impl<T: Serialize + DeserializeOwned> Serialize for Compressed<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer
    {
        let raw = bitcode::serialize(&self.value)
            .expect("bitcode serialisation failed");

        let bytes = compress(&raw, 3)
            .expect("compression failed");

        serializer.serialize_bytes(&bytes)
    }
}

struct CompressionVisitor;

impl<'de> Visitor<'de> for CompressionVisitor {
    type Value = Cow<'de, [u8]>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("expected bytes")
    }

    fn visit_borrowed_bytes<E>(self, v: &'de [u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Cow::Borrowed(v))
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Cow::Owned(v))
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Cow::Owned(v.to_vec()))
    }
}

impl<'de, T: Serialize + DeserializeOwned> Deserialize<'de> for Compressed<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>
    {
        let bytes = deserializer.deserialize_bytes(CompressionVisitor)?;

        let size = decompressed_size(&bytes)
            .ok_or(serde::de::Error::custom("failed to decompress data"))?;

        let raw = decompress(&bytes, size as usize)
            .map_err(|e| serde::de::Error::custom(
                format!("failed to decompress data: {e:?}")
            ))?;

        let value = bitcode::deserialize(&raw)
            .map_err(|e| serde::de::Error::custom(
                format!("failed to deserialise decompressed data: {e:?}")
            ))?;

        Ok(Self { value })
    }
}

/// A helper trait to compress data in a chained manner.
pub trait Compressable: Serialize + DeserializeOwned {
    fn compress(self) -> Compressed<Self>;
}

impl<T: Serialize + DeserializeOwned> Compressable for T {
    fn compress(self) -> Compressed<Self> {
        Compressed::new(self)
    }
}
