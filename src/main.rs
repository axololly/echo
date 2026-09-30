use vodozemac::megolm::{GroupSession, InboundGroupSession, SessionConfig as MegolmSessionConfig};

const CONFIG: MegolmSessionConfig = MegolmSessionConfig::version_1();

fn main() -> rootcause::Result<()> {
    // A group session is a one-to-many method of communication.
    // Alice's session does not know about Bob's session, and
    // Bob's session does not know about Alice's session.
    let mut alice_sender = GroupSession::new(CONFIG);
    let mut bob_sender = GroupSession::new(CONFIG);

    // Alice sends Bob a message.
    {
        // Bob needs Alice's session key to read her messages.
        let mut bob_reads_alice = InboundGroupSession::new(
            &alice_sender.session_key(),
            CONFIG
        );

        // Alice creates the message to be sent
        let alice_message = alice_sender.encrypt("hello bob");

        // Bob reads what Alice sent.
        let bob_received = bob_reads_alice.decrypt(&alice_message)?;

        println!("(from alice) bob received: {:?}", str::from_utf8(&bob_received.plaintext)?);
    }

    // Alice needs Bob's session key to read her messages.
    let mut alice_reads_bob = InboundGroupSession::new(
        &bob_sender.session_key(),
        CONFIG
    );

    // Bob creates the message to be sent
    let bob_message = bob_sender.encrypt("hello alice");

    // Bob sends Alice a message back.
    {
        // Alice reads what Bob sent.
        let alice_received = alice_reads_bob.decrypt(&bob_message)?;

        println!("(from bob) alice received: {:?}", str::from_utf8(&alice_received.plaintext)?);
    }

    // Alice re-reads Bob's message.
    {
        let alice_received = alice_reads_bob.decrypt(&bob_message)?;

        println!("(from bob 2) alice received: {:?}", str::from_utf8(&alice_received.plaintext)?);
    }

    Ok(())
}
