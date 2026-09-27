#![allow(unused)]

mod secret;
use secret::{Secret, Signed};

use p256::ecdsa::VerifyingKey;

fn main() {
    // The user has their own personal secret.
    let user_secret = Secret::random();

    // The user uploads the verifying key that should be used
    // by the server to check the authenticity of the user's
    // signatures.
    let user_signature_verifier: VerifyingKey = user_secret.into();

    // The server assigns them a public user ID.
    let user_id = 123;

    // When the user wants to authenticate, they can sign their
    // own ID and send that to the server.
    let signed_user_id: Signed<u64> = user_secret.sign(user_id);

    // The server would then get the signature verifier for
    // the user ID inside the Signed<UserID>, but we have
    // that already.

    // The server then checks if the signature is authentic.
    let is_authentic = signed_user_id.verify(
        &user_id,
        user_signature_verifier
    );

    // If it's authentic, they can be authenticated.
    // Otherwise, they have to be rejected.
    if is_authentic {
        println!("You have been authorised as user with ID {}", *signed_user_id);
    }
    else {
        println!("You are not authorised as user with ID {}", *signed_user_id);
    }
}
