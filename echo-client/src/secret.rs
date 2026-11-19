use echo_types::Secret;

/// A wrapper around [`Secret`] that derives new secrets
/// for different functions.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct MasterSecret(Secret);

impl MasterSecret {
    /// Create a new master secret from this given secret.
    pub fn random() -> Self {
        Self(Secret::random())
    }

    /// Derive the secret used for making [`Encrypted`] data.
    ///
    /// [`Encrypted`]: echo_types::Encrypted
    pub fn encryption_secret(&self) -> Secret {
        self.0.derive_new("encryption/symmetric")
    }

    /// Derive the secret used for making [`Signed`] data.
    ///
    /// [`Signed`]: echo_types::Signed
    pub fn signing_secret(&self) -> Secret {
        self.0.derive_new("signatures")
    }

    /// Derive a specific secret to be used when making
    /// [`CryptoBox`] instances for other users.
    ///
    /// [`CryptoBox`]: echo_types::CryptoBox
    pub fn box_secret(&self) -> Secret {
        self.0.derive_new("encryption/crypto-box")
    }
}

impl From<Secret> for MasterSecret {
    fn from(value: Secret) -> Self {
        Self(value)
    }
}

impl From<MasterSecret> for Secret {
    fn from(value: MasterSecret) -> Self {
        value.0
    }
}
