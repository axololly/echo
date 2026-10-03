use serde::Serialize;
use vodozemac::{megolm::{GroupSession, SessionConfig as MegolmSessionConfig}, olm::{Account, OlmMessage, SessionConfig}};

const CONFIG: MegolmSessionConfig = MegolmSessionConfig::version_1();

/// Serialize some data using [`bitcode`],
/// then measure and return the size of the
/// serialized payload.
fn size_of<T: Serialize>(data: &T) -> usize {
    bitcode::serialize(data).unwrap().len()
}

fn main() -> rootcause::Result<()> {
    println!("Olm sessions:");
    println!("================");

    let alice = Account::new();
    let mut bob = Account::new();

    let bob_otk = bob.generate_one_time_keys(1).created[0];

    bob.mark_keys_as_published();

    let mut alice_session = alice.create_outbound_session(
        SessionConfig::version_1(),
        bob.curve25519_key(),
        bob_otk
    )?;

    let mut alice_pickle_size = size_of(&alice_session.pickle());

    println!("size of alice's created session: {alice_pickle_size} bytes");

    let OlmMessage::PreKey(pre_key_message) = alice_session.encrypt([])? else {
        unreachable!()
    };

    alice_pickle_size = size_of(&alice_session.pickle());

    println!("size of alice's created session after message: {alice_pickle_size} bytes");

    let bob_session = bob.create_inbound_session(
        SessionConfig::version_1(),
        alice.curve25519_key(),
        &pre_key_message
    )?.session;

    let bob_pickle_size = size_of(&bob_session.pickle());

    println!("size of bob's created session: {bob_pickle_size} bytes");

    println!("size of created DM: {} bytes", alice_pickle_size + bob_pickle_size);

    println!();

    println!("Megolm sessions:");
    println!("================");

    let group_session = GroupSession::new(CONFIG);

    let pickle_size = size_of(&group_session.pickle());
    let session_key_size = size_of(&group_session.session_key());

    println!("size of group session pickle: {pickle_size} bytes");

    println!();

    println!("size of session key: {session_key_size} bytes");
    println!("size of 99 session keys: {} bytes", session_key_size * 99);

    let total_for_1_user = pickle_size + session_key_size * 99;

    println!("total size for 1 user: {total_for_1_user} bytes");

    println!();

    println!("total size for a 100-person group chat: {} bytes", total_for_1_user * 100);

    Ok(())
}
