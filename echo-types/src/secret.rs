use std::{array::TryFromSliceError, fmt::Debug, marker::PhantomData, ops::Deref, result::Result as StdResult};

use argon2::Argon2;
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce, aead::{Aead as _, Generate as _}};
use crypto_box::{aead::Aead as _, ChaChaBox};
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
        Encrypted::encrypt_with_key(value, self.0)
    }

    /// Decrypt some [`Encrypted`] data using this [`Secret`] as a key.
    pub fn decrypt<T>(&self, enc: &Encrypted<T>) -> DecryptionResult<T>
    where
        T: Serialize + DeserializeOwned
    {
        enc.decrypt(self.0)
    }

    /// Sign some data using this [`Secret`].
    pub fn sign<T: Serialize>(&self, value: T) -> Signed<T> {
        Signed::new(value, (*self).into())
    }

    /// Verify some data was made from this [`Secret`].
    pub fn verify<T: Serialize>(&self, signature: &Signed<T>) -> bool {
        signature.verify((*self).into())
    }

    /// Make a [`CryptoBox`] that can only be opened by whoever
    /// has the secret key corresponding to this public key.
    pub fn box_for<T>(
        &self,
        value: &T,
        public_key: crypto_box::PublicKey
    ) -> CryptoBox<T>
    where
        T: Serialize + DeserializeOwned
    {
        CryptoBox::new(value, *self, public_key)
    }

    /// Open a [`CryptoBox`] that was sent by whoever has the given public key.
    pub fn unbox_from<T>(
        &self,
        crypto_box: &CryptoBox<T>,
        public_key: crypto_box::PublicKey
    ) -> DecryptionResult<T>
    where
        T: Serialize + DeserializeOwned
    {
        crypto_box.unbox(*self, public_key)
    }

    /// Try to convert a byte slice into a [`Secret`].
    pub fn try_from_bytes(bytes: &[u8]) -> std::result::Result<Self, TryFromSliceError> {
        <[u8; 32]>::try_from(bytes).map(Self)
    }
}

impl AsRef<[u8]> for Secret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f
            .debug_struct("Secret")
            .finish_non_exhaustive()
    }
}

pub const KEY_SIZE: usize = 32;
pub type EncryptionKey = [u8; KEY_SIZE];

impl From<Secret> for EncryptionKey {
    fn from(value: Secret) -> Self {
        value.0
    }
}

impl From<Secret> for crypto_box::SecretKey {
    fn from(value: Secret) -> Self {
        crypto_box::SecretKey::from_bytes(value.0)
    }
}

impl From<Secret> for crypto_box::PublicKey {
    fn from(value: Secret) -> Self {
        crypto_box::SecretKey::from_bytes(value.0).public_key()
    }
}

impl From<Secret> for SigningKey {
    fn from(value: Secret) -> Self {
        SigningKey::from_slice(&value.0)
            .expect("failed to convert secret to signing key")
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

#[derive(Deserialize, Serialize)]
pub struct Encrypted<T> {
    payload: Vec<u8>,
    nonce: [u8; NONCE_SIZE],
    _data: PhantomData<T>,
}

impl<T> Encrypted<T> {
    /// Change the marker type of this [`Encrypted`] struct.
    ///
    /// # Safety
    /// This is just changing the type that would be returned
    /// from decrypting this struct.
    ///
    /// Unless `T` and `U` deserialise identically, the
    /// deserialisation part will just fail.
    pub unsafe fn cast<U>(self) -> Encrypted<U> {
        let Encrypted {
            payload,
            nonce,
            ..
        } = self;

        Encrypted {
            payload,
            nonce,
            _data: PhantomData
        }
    }
}

impl<T> PartialEq for Encrypted<T> {
    fn eq(&self, other: &Self) -> bool {
        self.payload == other.payload && self.nonce == other.nonce
    }
}

impl<T> Eq for Encrypted<T> {}

impl<T> Clone for Encrypted<T> {
    fn clone(&self) -> Self {
        Self {
            payload: self.payload.clone(),
            nonce: self.nonce,
            _data: PhantomData
        }
    }
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

    pub fn unlock(&self, password: &str) -> DecryptionResult<T> {
        let argon2 = construct_argon2();

        let mut key = [0; ARGON2_OUT_SIZE];

        argon2
            .hash_password_into(password.as_bytes(), &self.salt, &mut key)
            .expect("failed to hash with argon2");

        self.enc.decrypt(key)
    }
}

impl<T: DeserializeOwned> Decode<'_, sqlx::Postgres> for PasswordProtected<T> {
    fn decode(
        value: <sqlx::Postgres as sqlx::Database>::ValueRef<'_>
    ) -> StdResult<Self, sqlx::error::BoxDynError> {
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

#[derive(Clone, Deserialize, Serialize)]
pub struct Signed<T> {
    value: T,
    raw: P256Signature
}

impl<T: Copy> Copy for Signed<T> {}

impl<T: Serialize> Signed<T> {
    pub fn new(value: T, key: SigningKey) -> Self {
        let bytes = bitcode::serialize(&value)
            .expect("failed to serialise with bitcode");

        let raw = key.sign(&bytes);

        Self {
            value,
            raw
        }
    }

    pub fn verify(&self, verifier: SignatureVerifier) -> bool {
        let bytes = bitcode::serialize(&self.value)
            .expect("failed to serialise with bitcode");

        verifier.0.verify(&bytes, &self.raw).is_ok()
    }

    pub fn value(&self) -> &T {
        &self.value
    }
}

impl<T: Debug> Debug for Signed<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f
            .debug_struct("Signed")
            .field("value", &self.value)
            .finish_non_exhaustive()
    }
}

impl<T> Deref for Signed<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct CryptoBox<T> {
    payload: Vec<u8>,
    nonce: [u8; 24],
    _data: PhantomData<T>
}

impl<T: Serialize> CryptoBox<T> {
    pub fn new(value: &T, secret: Secret, public_key: crypto_box::PublicKey) -> Self {
        let bytes = bitcode::serialize(&value).expect("failed to serialise");

        let inner = ChaChaBox::new(&public_key, &secret.into());

        let nonce = rand::random::<[u8; 24]>();

        let payload = inner
            .encrypt(crypto_box::Nonce::from_slice(&nonce), &*bytes)
            .expect("failed to encrypt");

        Self {
            payload,
            nonce,
            _data: PhantomData
        }
    }
}

impl<T: DeserializeOwned> CryptoBox<T> {
    pub fn unbox(&self, secret: Secret, public_key: crypto_box::PublicKey) -> DecryptionResult<T> {
        let inner = crypto_box::ChaChaBox::new(&public_key, &secret.into());

        let bytes = inner
            .decrypt(&self.nonce.into(), &*self.payload)
            .context(DecryptionError::Decryption)?;

        let obj = bitcode::deserialize(&bytes)
            .context(DecryptionError::Deserialisation)?;

        Ok(obj)
    }
}

impl<T> Debug for CryptoBox<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CryptoBox").finish_non_exhaustive()
    }
}

impl<T> sqlx::Encode<'_, sqlx::Postgres> for CryptoBox<T> {
    fn encode_by_ref(
        &self,
        buf: &mut <sqlx::Postgres as sqlx::Database>::ArgumentBuffer,
    ) -> StdResult<IsNull, sqlx::error::BoxDynError> {
        let bytes = bitcode::serialize(self)?;

        buf.extend_from_slice(&bytes);

        Ok(IsNull::No)
    }
}

impl<T> sqlx::Decode<'_, sqlx::Postgres> for CryptoBox<T> {
    fn decode(
        value: <sqlx::Postgres as sqlx::Database>::ValueRef<'_>
    ) -> StdResult<Self, sqlx::error::BoxDynError> {
        let bytes = value.as_bytes()?;

        let obj = bitcode::deserialize(bytes)?;

        Ok(obj)
    }
}

impl<T> sqlx::Type<sqlx::Postgres> for CryptoBox<T> {
    fn type_info() -> <sqlx::Postgres as sqlx::Database>::TypeInfo {
        <Vec<u8> as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

// TODO: add a master secret type that can derive its own keys for different functions
