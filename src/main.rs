use std::marker::PhantomData;

use chacha20poly1305::{KeyInit, XChaCha20Poly1305, aead::Aead};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

/// A secret.
///
/// Secrets are small 32-byte objects that can be used as keys
/// for encrypting data, signing data and deriving new keys
/// through a HKDF.
#[derive(Clone, Copy)]
struct Secret([u8; 32]);

impl Secret {
    /// Generate a random secret.
    pub fn random() -> Self {
        Self(rand::random())
    }

    /// Encrypt some data using this secret.
    pub fn encrypt<T: DeserializeOwned + Serialize>(&self, data: &T) -> Encrypted<T> {
        Encrypted::encrypt(data, *self)
    }

    /// Decrypt an [`Encrypted`] struct using this secret.
    pub fn decrypt<T: DeserializeOwned + Serialize>(&self, enc: &Encrypted<T>) -> Result<T, DecryptionError> {
        enc.decrypt(*self)
    }
}

/// Some encrypted data.
///
/// Data is serialised before encryption and deserialised
/// after encryption using [`serde`].
#[derive(Clone, Deserialize, Serialize)]
struct Encrypted<T> {
    payload: Vec<u8>,
    nonce: [u8; 24],
    _data: PhantomData<T>
}

/// An error related to decryption.
#[derive(Clone, Copy, Debug)]
enum DecryptionError {
    /// Cannot decrypt the data
    UnableToDecrypt,
    /// Decrypted data could not be deserialised
    UnableToDeserialise
}

impl<T: DeserializeOwned + Serialize> Encrypted<T> {
    pub fn encrypt(data: &T, secret: Secret) -> Self {
        let nonce: [u8; 24] = rand::random();

        let cipher = XChaCha20Poly1305::new(&secret.0.into());

        let bytes = bitcode::serialize(data)
            .expect("failed to serialise");

        let payload = cipher
            .encrypt(&nonce.into(), bytes.as_ref())
            .expect("failed to encrypt data");

        Self {
            payload,
            nonce,
            _data: PhantomData
        }
    }

    pub fn decrypt(&self, secret: Secret) -> Result<T, DecryptionError> {
        let cipher = XChaCha20Poly1305::new(&secret.0.into());

        let plaintext = cipher
            .decrypt(&self.nonce.into(), &*self.payload)
            .map_err(|_| DecryptionError::UnableToDecrypt)?;

        bitcode::deserialize(&plaintext)
            .map_err(|_| DecryptionError::UnableToDeserialise)
    }
}


fn main() {
    let secret = Secret::random();

    let message = "this is some data".to_string();

    let enc = secret.encrypt(&message);

    let decrypted_message = secret.decrypt(&enc);

    println!("message: {message:?}");
    println!("decrypted message: {decrypted_message:?}");

    let secret2 = Secret::random();

    let decrypted_message2 = secret2
        .decrypt(&enc)
        .expect("failed to decrypt");

    println!("decrypted message from another secret: {decrypted_message2:?}");
}
