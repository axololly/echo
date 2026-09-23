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
}

fn main() {
    let secret = Secret::random();

    println!("secret bytes: {:?}", secret.0);
}
