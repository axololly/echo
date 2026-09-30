use vodozemac::olm::{Account, OlmMessage, SessionConfig as OlmSessionConfig};

fn main() -> rootcause::Result<()> {
    let alice = Account::new();
    let mut bob = Account::new();

    // One-time keys are used for Olm's 3DH, which lets two users have any number
    // of unique channels between one another.
    // Basic DH would only allow one session between two users, so it cannot be
    // replaced if compromised.
    bob.generate_one_time_keys(1);

    let bob_otk = *bob.one_time_keys().values().next().unwrap();

    bob.mark_keys_as_published();

    // Create a 1-on-1 session only on Alice's side.
    let mut alice_session = alice.create_outbound_session(
        OlmSessionConfig::version_1(),
        bob.curve25519_key(),
        bob_otk
    )?;

    // Create a pre-key message that Bob can use to complete his end of the 1-on-1 session.
    let OlmMessage::PreKey(pre_key_msg) = alice_session.encrypt([])? else {
        unreachable!()
    };

    // Bob can now receive messages from Alice
    let mut bob_session = bob.create_inbound_session(
        OlmSessionConfig::version_1(),
        alice.curve25519_key(),
        &pre_key_msg
    )?.session;

    // Alice decides to send Bob a message, and Bob reads it.
    {
        let alice_message = alice_session.encrypt("hello bob")?;

        let plaintext = bob_session.decrypt(&alice_message)?;

        let text = str::from_utf8(&plaintext)?;

        println!("(bob) alice said: {text:?}");
    }

    let bob_message = bob_session.encrypt("hello alice")?;

    // Bob decides to send Alice a message, and Alice reads it.
    {
        let plaintext = alice_session.decrypt(&bob_message)?;

        let text = str::from_utf8(&plaintext)?;

        println!("(alice) bob said: {text:?}");
    }

    // Alice then tries to decrypt Bob's message again.
    {
        let plaintext = alice_session.decrypt(&bob_message)?;

        let text = str::from_utf8(&plaintext)?;

        println!("(alice 2) bob said: {text:?}");
    }

    Ok(())
}
