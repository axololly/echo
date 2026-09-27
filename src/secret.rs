use std::{fmt::Debug, marker::PhantomData, ops::Deref};

use argon2::Argon2;
use chacha20poly1305::{
    Key, KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Generate},
};
use hkdf::Hkdf;
use p256::ecdsa::{Signature as P256Signature, SigningKey, VerifyingKey, signature::{Signer, Verifier}};
use rootcause::{Result, prelude::ResultExt};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::Sha256;
use thiserror::Error;

/// Secret data used for identification and crytography.
#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[repr(transparent)]
pub struct Secret([u8; 32]);

impl Secret {
    /// Derive a new [`Secret`] deterministically from this one.
    pub fn derive_new(&self, label: &str) -> Self {
        let hkdf = Hkdf::<Sha256>::new(None, &self.0);

        let mut okm = [0; 32];

        hkdf.expand(label.as_bytes(), &mut okm).expect("failed hkdf");

        Self(okm)
    }

    /// Generate a random [`Secret`].
    pub fn random() -> Self {
        Self(rand::random())
    }

    /// Encrypt some data using this [`Secret`] as a key.
    pub fn encrypt<T>(&self, value: &T) -> Encrypted<T>
    where
        T: Serialize + DeserializeOwned
    {
        Encrypted::encrypt_with_key(value, self.derive_new("encryption").0)
    }

    /// Decrypt some [`Encrypted`] data using this [`Secret`] as a key.
    pub fn decrypt<T>(&self, enc: &Encrypted<T>) -> DecryptionResult<T>
    where
        T: Serialize + DeserializeOwned
    {
        enc.decrypt(self.derive_new("encryption").0)
    }

    /// Sign some data using this [`Secret`].
    pub fn sign<T: Serialize>(&self, value: T) -> Signed<T> {
        let key = SigningKey::from_slice(&self.0)
            .expect("failed to create signing key");

        Signed::new(value, key)
    }

    /// Verify some data was signed with this [`Secret`].
    pub fn verify<T: Serialize>(&self, value: &T, signature: &Signed<T>) -> bool {
        signature.verify(value, (*self).into())
    }
}

pub const KEY_SIZE: usize = 32;
pub type EncryptionKey = [u8; KEY_SIZE];

impl From<Secret> for EncryptionKey {
    fn from(value: Secret) -> Self {
        value.0
    }
}

impl From<Secret> for VerifyingKey {
    fn from(value: Secret) -> Self {
        let signing_key = SigningKey::from_slice(&value.0)
            .expect("failed to convert secret to signing key");

        *signing_key.verifying_key()
    }
}

impl From<Secret> for SignatureVerifier {
    fn from(value: Secret) -> Self {
        let verifying_key: VerifyingKey = value.into();

        SignatureVerifier(verifying_key)
    }
}

pub const NONCE_SIZE: usize = 24;

/// An encrypted wrapper of some data.
///
/// This struct is typed so that the compiler understands
/// how to deserialise the decrypted output.
///
/// Encryption is done symmetrically using ChaCha20Poly1305.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct Encrypted<T> {
    payload: Vec<u8>,
    nonce: [u8; NONCE_SIZE],
    _data: PhantomData<T>,
}

impl<T> Debug for Encrypted<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f
            .debug_struct("Encrypted")
            .finish_non_exhaustive()
    }
}

/// An error related to decryption.
#[derive(Debug, Error)]
pub enum DecryptionError {
    /// Decryption worked, but deserialisation failed.
    #[error("failed to deserialise")]
    Deserialisation,

    /// Decryption failed entirely.
    #[error("failed to decrypt")]
    Decryption,
}

pub type DecryptionResult<T> = Result<T, DecryptionError>;

impl<T: Serialize + DeserializeOwned> Encrypted<T> {
    /// Encrypts some data using a random key, then returns
    /// the [`Encrypted`] instance and the key used for the
    /// encryption.
    ///
    /// To use an external key, call [`encrypt_with_key()`]
    /// instead.
    ///
    /// [`encrypt_with_key()`]: Encrypted::encrypt_with_key
    pub fn encrypt(value: &T) -> (Self, EncryptionKey) {
        let key = Key::generate().into();

        let enc = Self::encrypt_with_key(value, key);

        (enc, key)
    }

    /// Encrypts some data using a given key, and returns only the
    /// [`Encrypted`] instance.
    ///
    /// To use a random key, call [`encrypt()`] instead.
    ///
    /// # Panics
    ///
    /// If this function encounters an error related to serialisation
    /// or encryption, it will panic. This behaviour is chosen because
    /// failure here is unlikely and catastrophic.
    ///
    /// [`encrypt()`]: Encrypted::encrypt
    pub fn encrypt_with_key(value: &T, key: EncryptionKey) -> Self {
        let bytes = bitcode::serialize(value)
            .expect("failed to serialise with bitcode");

        let nonce = XNonce::generate();

        let cipher = XChaCha20Poly1305::new(&key.into());

        let payload = cipher
            .encrypt(&nonce, bytes.as_slice())
            .expect("failed to encrypt with cipher");

        Self {
            payload,
            nonce: nonce.into(),
            _data: PhantomData,
        }
    }

    /// Decrypt and deserialise this [`Encrypted`] wrapper to yield
    /// an owned `T` or an error.
    pub fn decrypt(&self, key: EncryptionKey) -> DecryptionResult<T> {
        use DecryptionError as E;

        let cipher = XChaCha20Poly1305::new(&key.into());

        let bytes = cipher
            .decrypt(&self.nonce.into(), self.payload.as_slice())
            .context(E::Decryption)?;

        bitcode::deserialize(&bytes).context(E::Deserialisation)
    }
}

pub const ARGON2_OUT_SIZE: usize = 32;

/// Construct an [`Argon2`] instance.
///
/// This function is used instead of the [`Default`]
/// implementation of [`Argon2`] to ensure it's stable.
/// If the implementation ever changed, the instance
/// would produce invalid hashes and cause breakage.
pub fn construct_argon2() -> Argon2<'static> {
    let params = argon2::Params::new(
        65_536, // memory, 64KB
        3, // iterations
        4, // number of threads
        Some(ARGON2_OUT_SIZE)
    ).expect("invalid argon2 parameters");

    Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params
    )
}

pub const ARGON2_SALT_SIZE: usize = 16;
pub type Argon2Salt = [u8; ARGON2_SALT_SIZE];

/// A password-protected wrapper of some data.
///
/// This works by using [`argon2`] to compute an encryption key
/// from a password, and then use said encryption key to unlock
/// an [`Encrypted`] instance.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct PasswordProtected<T> {
    enc: Encrypted<T>,
    salt: Argon2Salt,
}

impl<T: Serialize + DeserializeOwned> PasswordProtected<T> {
    /// Encrypt some data using a given password.
    ///
    /// # Panics
    ///
    /// This will panic if an error occurs during password
    /// hashing using [`argon2`], or if any situations
    /// documented in [`Encrypted::encrypt_with_key`] are
    /// encountered.
    pub fn new(value: &T, password: &str) -> Self {
        let argon2 = construct_argon2();

        let mut key = [0; ARGON2_OUT_SIZE];

        let salt: Argon2Salt = rand::random();

        argon2
            .hash_password_into(password.as_bytes(), &salt, &mut key)
            .expect("failed to hash with argon2");

        let enc = Encrypted::encrypt_with_key(value, key);

        Self { enc, salt }
    }

    /// Decrypt this [`PasswordProtected`] instance using a given password.
    ///
    /// # Panics
    ///
    /// This will panic if an error occurs during password
    /// hashing using [`argon2`].
    pub fn unlock(&self, password: &str) -> DecryptionResult<T> {
        let argon2 = construct_argon2();

        let mut key = [0; ARGON2_OUT_SIZE];

        argon2
            .hash_password_into(password.as_bytes(), &self.salt, &mut key)
            .expect("failed to hash with argon2");

        self.enc.decrypt(key)
    }
}

impl<T> Debug for PasswordProtected<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f
            .debug_struct("PasswordProtected")
            .finish_non_exhaustive()
    }
}

/// A [`sqlx`]-compliant wrapper around [`p256`]'s [`VerifyingKey`] type.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[repr(transparent)]
pub struct SignatureVerifier(VerifyingKey);

/// A value with a signature appended.
///
/// The original data is still recoverable through
/// dereferencing, but the struct is meant to be
/// immutable.
#[derive(Deserialize, Serialize)]
pub struct Signed<T> {
    value: T,
    raw: P256Signature,
    author: VerifyingKey,
    _data: PhantomData<T>
}

impl<T: Serialize> Signed<T> {
    /// Sign some data using the given [`SigningKey`].
    ///
    /// # Panics
    ///
    /// This function will panic if serialising [`value`]
    /// produces an error.
    pub fn new(value: T, key: SigningKey) -> Self {
        let bytes = bitcode::serialize(&value)
            .expect("failed to serialise with bitcode");

        let raw = key.sign(&bytes);

        Self {
            value,
            raw,
            author: *key.verifying_key(),
            _data: PhantomData
        }
    }

    /// Verify that the signature on this [`Signed`] instance
    /// is authentic for a given value.
    ///
    /// This does not compare if the value on this struct
    /// and the value in the parameter are equal.
    pub fn verify(&self, value: &T, verifier: VerifyingKey) -> bool {
        let bytes = bitcode::serialize(&value)
            .expect("failed to serialise with bitcode");

        verifier.verify(&bytes, &self.raw).is_ok()
    }
}

impl<T> Deref for Signed<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}
