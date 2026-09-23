#![allow(unused)]

use std::{marker::PhantomData, ops::Deref};

use chacha20poly1305::{KeyInit, XChaCha20Poly1305, aead::Aead};
use hex_literal::hex;
use hkdf::Hkdf;
use p256::{PublicKey, SecretKey, ecdsa::{Signature as RawSignature, SigningKey, signature::{Signer, Verifier}}};
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
    /// Generate a random [`Secret`].
    pub fn random() -> Self {
        Self(rand::random())
    }

    /// Derive a new cryptographically secure (but determinant) secret
    /// from this secret and a label. The label is used to individualise
    /// each secret.
    pub fn derive_new(&self, info: &str) -> Self {
        let hkdf = Hkdf::<Sha256>::new(None, &self.0);

        let mut out = [0; 32];

        hkdf.expand(info.as_bytes(), &mut out).expect("HKDF failed");

        Self(out)
    }

    /// Encrypt some data using this [`Secret`].
    pub fn encrypt<T: DeserializeOwned + Serialize>(&self, data: &T) -> Encrypted<T> {
        Encrypted::encrypt(data, *self)
    }

    /// Decrypt an [`Encrypted`] struct using this [`Secret`].
    pub fn decrypt<T: DeserializeOwned + Serialize>(&self, enc: &Encrypted<T>) -> Result<T, DecryptionError> {
        enc.decrypt(*self)
    }

    /// Sign some data using this [`Secret`].
    pub fn sign<T: Serialize>(&self, data: T) -> Signed<T> {
        Signed::new(data, *self)
    }

    /// Verify a [`Signed`] was created using this [`Secret`].
    pub fn verify<T: Serialize>(&self, signed: &Signed<T>) -> bool {
        signed.verify(*self)
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

/// A signed value, where the signature is computed based
/// on the bytes outputted from serialising the value.
///
/// This also packages the original value.
#[derive(Deserialize, Serialize)]
struct Signed<T> {
    inner: T,
    signature: RawSignature
}

impl<T: Serialize> Signed<T> {
    /// Create a new signed value, using the secret as the signing key.
    pub fn new(data: T, secret: Secret) -> Self {
        let bytes = bitcode::serialize(&data)
            .expect("failed to serialise");

        let signing_key = SigningKey::from_bytes(&secret.0.into())
            .expect("failed to create signing key from Secret");

        let signature = signing_key.sign(&bytes);

        Self {
            inner: data,
            signature
        }
    }

    /// Verify that the given [`Secret`] was used to create this signature.
    pub fn verify(&self, secret: Secret) -> bool {
        let signing_key = SigningKey::from_bytes(&secret.0.into())
            .expect("failed to create signing key from Secret");

        let bytes = bitcode::serialize(&self.inner)
            .expect("failed to serialise");

        signing_key
            .verifying_key()
            .verify(&bytes, &self.signature)
            .is_ok()
    }
}

// Allows you to access the original value from outside
impl<T> Deref for Signed<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

fn main() {
    let secret = Secret::random();

    let num = 15;

    let signed_num = secret.sign(num);

    assert!(secret.verify(&signed_num));

    println!("original number: {}", *signed_num);
}
