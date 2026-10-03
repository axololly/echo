mod group_storage;
use group_storage::MyGroupStorage;

use mls_rs::{CipherSuite, CipherSuiteProvider, Client, CryptoProvider, ExtensionList, client_builder::{BaseConfig, WithCryptoProvider, WithGroupStateStorage, WithIdentityProvider}, group::{CommitOutput, ReceivedMessage}, identity::{SigningIdentity, basic::BasicIdentityProvider}};
use mls_rs_core::identity::BasicCredential;
use mls_rs_crypto_rustcrypto::RustCryptoProvider;

const CIPHER_SUITE: CipherSuite = CipherSuite::CURVE25519_CHACHA;

type ClientConfig = WithGroupStateStorage<
    MyGroupStorage,
    WithCryptoProvider<
        RustCryptoProvider,
        WithIdentityProvider<
            BasicIdentityProvider,
            BaseConfig
        >
    >
>;

/// Create an MLS client where the identity is a given username.
fn make_client(username: &str) -> Client<ClientConfig> {
    // Make a basic identifier with no authentication.
    let credential = BasicCredential::new(username.as_bytes().to_vec());

    // Generate an Ed25519 signature key pair used for authenticity.
    let (private_key, public_key) = RustCryptoProvider::new()
        .cipher_suite_provider(CIPHER_SUITE)
        .expect("cipher suite provider not found")
        .signature_key_generate()
        .expect("cannot generate signature keys");

    // Create a group member identity from the public identifier and the generated public key.
    let identity = SigningIdentity::new(
        credential.into_credential(),
        public_key
    );

    // Build the client with the options we chose.
    Client::builder()
        .crypto_provider(RustCryptoProvider::new())
        .group_state_storage(MyGroupStorage::default()) // Use my custom group state storage
        .signing_identity(identity, private_key, CIPHER_SUITE)
        .identity_provider(BasicIdentityProvider::new())
        .build()
}

fn main() -> rootcause::Result<()> {
    let alice = make_client("alice");
    let bob = make_client("bob");

    // MLS only has groups where multiple clients exchange messages.
    // Let's say Alice creates one and decides to invite Bob.
    let mut alice_group = alice.create_group(
        ExtensionList::new(),
        ExtensionList::new(),
        None
    )?;

    // A key package contains public keys used to add a client into
    // a group chat. These are precomputed and uploaded on a central
    // server, so that you can be added to a group chat offline.
    let bob_key_pkg = bob.generate_key_package_message(
        ExtensionList::new(),
        ExtensionList::new(),
        None
    )?;

    // MLS groups are decentralised, so you have to propose membership
    // changes to other members. If you apply the change to your own
    // group instance, but nobody else does, they won't be able to
    // decrypt your messages because their group state is not the same
    // as yours.
    alice_group.propose_add(
        bob_key_pkg,
        vec![]
    )?;

    let CommitOutput {
        // The message to be sent to everyone else so
        // they can process the addition and decide to
        // respect or refute it.
        commit_message,

        // Bob's welcome message is in here
        welcome_messages,
        ..
    } = alice_group.commit(vec![])?;

    alice_group.process_incoming_message(commit_message)?;

    // Group state specifically addressed to Bob is in this list of welcome messages.
    let bob_welcome_msg = &welcome_messages[0];

    // Bob can now join the group with this welcome message he was sent.
    let (mut bob_group, _info) = bob.join_group(
        None,
        bob_welcome_msg,
        None
    )?;

    let alice_message = alice_group.encrypt_application_message(
        b"hello bob",
        vec![]
    )?;

    // MLS messages could be proposals, group state updates or regular messages,
    // hence why we need to match over them.
    let received = bob_group.process_incoming_message(alice_message)?;

    match received {
        ReceivedMessage::ApplicationMessage(desc) => {
            let member = bob_group
                .member_at_index(desc.sender_index)
                .expect("no member at that index");

            let sender_identifier = member
                .signing_identity
                .credential
                .as_basic()
                .expect("expected a basic credential, got something else")
                .identifier();

            println!("received data {:?} from sender {:?}", str::from_utf8(desc.data())?, str::from_utf8(sender_identifier)?);
        },
        _ => println!("received different type of message: {received:?}")
    }

    alice_group.write_to_storage()?;
    bob_group.write_to_storage()?;

    println!("alice group size: {}", alice.group_state_storage().serialized_size());
    println!("bob group size: {}", bob.group_state_storage().serialized_size());

    Ok(())
}
