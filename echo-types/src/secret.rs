use std::{fmt::Debug, marker::PhantomData, ops::Deref, result::Result as StdResult};

use argon2::Argon2;
use chacha20poly1305::{
    Key, KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Generate},
};
use hkdf::Hkdf;
use rootcause::{Result, prelude::ResultExt};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::Sha256;
use sqlx::{Decode, Encode, encode::IsNull, postgres::PgTypeInfo};
use thiserror::Error;

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
        let signature_secret = self.derive_new("signing");

        let key = SigningKey::from_slice(&signature_secret.0)
            .expect("failed to create signing key");

        Signed::new(value, key)
    }

    /// Verify some data was made from this [`Secret`].
    pub fn verify<T: Serialize>(&self, value: &T, signature: &Signed<T>) -> bool {
        let signing_secret = self.derive_new("signing");

        signature.verify(value, signing_secret.into())
    }
}

pub const KEY_SIZE: usize = 32;
pub type EncryptionKey = [u8; KEY_SIZE];

impl From<Secret> for EncryptionKey {
    fn from(value: Secret) -> Self {
        value.0
    }
}

impl From<Secret> for SignatureVerifier {
    fn from(value: Secret) -> Self {
        let key = SigningKey::from_slice(&value.0)
            .expect("failed to convert secret to signing key");

        SignatureVerifier(*key.verifying_key())
    }
}

pub const NONCE_SIZE: usize = 24;

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

#[derive(Debug, Error)]
pub enum DecryptionError {
    #[error("failed to deserialise")]
    Deserialisation,

    #[error("failed to decrypt")]
    Decryption,
}

pub type DecryptionResult<T> = Result<T, DecryptionError>;

pub const ARGON2_OUT_SIZE: usize = 32;

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

impl<T: Serialize + DeserializeOwned> Encrypted<T> {
    pub fn encrypt(value: &T) -> (Self, EncryptionKey) {
        let key = Key::generate().into();

        let enc = Self::encrypt_with_key(value, key);

        (enc, key)
    }

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

    pub fn decrypt(&self, key: EncryptionKey) -> DecryptionResult<T> {
        use DecryptionError as E;

        let cipher = XChaCha20Poly1305::new(&key.into());

        let bytes = cipher
            .decrypt(&self.nonce.into(), self.payload.as_slice())
            .context(E::Decryption)?;

        bitcode::deserialize(&bytes).context(E::Deserialisation)
    }
}

impl<T> Encode<'_, sqlx::Postgres> for Encrypted<T> {
    fn encode_by_ref(
        &self,
        buf: &mut <sqlx::Postgres as sqlx::Database>::ArgumentBuffer,
    ) -> StdResult<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        let bytes = bitcode::serialize(self)?;

        buf.extend_from_slice(&bytes);

        Ok(IsNull::No)
    }
}

impl<T> Decode<'_, sqlx::Postgres> for Encrypted<T> {
    fn decode(value: <sqlx::Postgres as sqlx::Database>::ValueRef<'_>) -> StdResult<Self, sqlx::error::BoxDynError> {
        let bytes = value.as_bytes()?;

        let obj = bitcode::deserialize(bytes)?;

        Ok(obj)
    }
}

impl<T> sqlx::Type<sqlx::Postgres> for Encrypted<T> {
    fn type_info() -> PgTypeInfo {
        <Vec<u8> as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

pub const ARGON2_SALT_SIZE: usize = 16;
pub type Argon2Salt = [u8; ARGON2_SALT_SIZE];

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct PasswordProtected<T> {
    enc: Encrypted<T>,
    salt: Argon2Salt,
}

impl<T: Serialize + DeserializeOwned> PasswordProtected<T> {
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
}

impl<T: DeserializeOwned> Decode<'_, sqlx::Postgres> for PasswordProtected<T> {
    fn decode(value: <sqlx::Postgres as sqlx::Database>::ValueRef<'_>) -> StdResult<Self, sqlx::error::BoxDynError> {
        let obj = bitcode::deserialize(value.as_bytes()?)?;

        Ok(obj)
    }
}

impl<T: Serialize> Encode<'_, sqlx::Postgres> for PasswordProtected<T> {
    fn encode_by_ref(
        &self,
        buf: &mut <sqlx::Postgres as sqlx::Database>::ArgumentBuffer,
    ) -> StdResult<sqlx::encode::IsNull, sqlx::error::BoxDynError>
    {
        let bytes = bitcode::serialize(self)?;

        buf.extend_from_slice(&bytes);

        Ok(sqlx::encode::IsNull::No)
    }
}

impl<T> Debug for PasswordProtected<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f
            .debug_struct("PasswordProtected")
            .finish_non_exhaustive()
    }
}

impl<T> sqlx::Type<sqlx::Postgres> for PasswordProtected<T> {
    fn type_info() -> PgTypeInfo {
        <Vec<u8> as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

use p256::ecdsa::{Signature as P256Signature, SigningKey, VerifyingKey, signature::{Signer, Verifier}};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[repr(transparent)]
pub struct SignatureVerifier(VerifyingKey);

impl sqlx::Encode<'_, sqlx::Postgres> for SignatureVerifier {
    fn encode_by_ref(
        &self,
        buf: &mut <sqlx::Postgres as sqlx::Database>::ArgumentBuffer,
    ) -> StdResult<IsNull, sqlx::error::BoxDynError> {
        buf.extend_from_slice(&self.0.to_sec1_bytes());

        Ok(IsNull::No)
    }
}

impl sqlx::Decode<'_, sqlx::Postgres> for SignatureVerifier {
    fn decode(value: <sqlx::Postgres as sqlx::Database>::ValueRef<'_>) -> StdResult<Self, sqlx::error::BoxDynError> {
        let key = VerifyingKey::from_sec1_bytes(value.as_bytes()?)?;

        Ok(Self(key))
    }
}

impl sqlx::Type<sqlx::Postgres> for SignatureVerifier {
    fn type_info() -> <sqlx::Postgres as sqlx::Database>::TypeInfo {
        <Vec<u8> as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

#[derive(Deserialize, Serialize)]
pub struct Signed<T> {
    value: T,
    raw: P256Signature,
    author: VerifyingKey,
    _data: PhantomData<T>
}

impl<T: Serialize> Signed<T> {
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

    pub fn verify(&self, value: &T, verifier: SignatureVerifier) -> bool {
        let bytes = bitcode::serialize(&value)
            .expect("failed to serialise with bitcode");

        verifier.0.verify(&bytes, &self.raw).is_ok()
    }

    pub fn value(&self) -> &T {
        &self.value
    }
}

impl<T> Deref for Signed<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}
