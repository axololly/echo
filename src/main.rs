use serde::Serialize;
use vodozemac::{megolm::{GroupSession, InboundGroupSession, SessionConfig as MegolmSessionConfig}, olm::{Account, OlmMessage, SessionConfig}};

const CONFIG: MegolmSessionConfig = MegolmSessionConfig::version_1();

fn size_of<T: Serialize>(data: &T) -> usize {
    bitcode::serialize(data).unwrap().len()
}

fn main() -> rootcause::Result<()> {
    println!("Olm sessions:");
    println!("================");

    let mut alice = Account::new();
    let mut bob = Account::new();

    let bob_otk = bob.generate_one_time_keys(1).created[0];

    bob.mark_keys_as_published();

    let mut alice_session = alice.create_outbound_session(
        SessionConfig::version_1(),
        bob.curve25519_key(),
        bob_otk
    )?;

    println!("size of alice's created session: {} bytes", size_of(&alice_session.pickle()));

    let OlmMessage::PreKey(pre_key_message) = alice_session.encrypt([])? else {
        unreachable!()
    };

    println!("size of alice's created session after message: {} bytes", size_of(&alice_session.pickle()));

    let bob_session = bob.create_inbound_session(
        SessionConfig::version_1(),
        alice.curve25519_key(),
        &pre_key_message
    )?.session;

    println!("size of bob's created session: {} bytes", size_of(&bob_session.pickle()));

    println!("size of created DM: {} bytes", size_of(&alice_session.pickle()) + size_of(&bob_session.pickle()));

    println!();

    println!("Megolm sessions:");
    println!("================");

    let group_session = GroupSession::new(CONFIG);

    println!("size of group session pickle: {} bytes", size_of(&group_session.pickle()));

    println!();

    println!("size of session key: {} bytes", size_of(&group_session.session_key()));
    println!("size of 99 session keys: {} bytes", size_of(&group_session.session_key()) * 99);

    let total_for_1_user = size_of(&group_session.pickle()) + size_of(&group_session.session_key()) * 99;

    println!("total size for 1 user: {total_for_1_user} bytes");

    println!();

    println!("total size for a 100-person group chat: {} bytes", total_for_1_user * 100);

    Ok(())
}
