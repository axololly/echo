use std::marker::PhantomData;

use chacha20poly1305::{KeyInit, XChaCha20Poly1305, aead::Aead};
use hex_literal::hex;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::Sha256;

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

    /// Derive a new cryptographically secure, but determinant, secret
    /// from this secret and a label.
    ///
    /// The label is used to individualise each secret.
    pub fn derive_new(&self, info: &str) -> Self {
        let hkdf = Hkdf::<Sha256>::new(None, &self.0);

        let mut out = [0; 32];

        hkdf.expand(info.as_bytes(), &mut out).expect("HKDF failed");

        Self(out)
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
    let secret = Secret(hex!("4d331c19d8889e640325fad19e0d11dcf2ae5b649b48e72c8ad83d4b05bc9802"));

    let encryption_secret = secret.derive_new("encryption");

    assert_eq!(
        encryption_secret.0, hex!("53d6935e82f8ba1550d98b8a45e362aa50473f4378c2928c8a38f9a6b1f05914"),
        "HKDF was not deterministic"
    );

    println!("Assertion passed.")
}
