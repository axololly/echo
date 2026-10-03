mod group_storage;
use group_storage::MyGroupStorage;

use mls_rs::{CipherSuite, CipherSuiteProvider, Client, CryptoProvider, ExtensionList, Group, client_builder::{BaseConfig, WithCryptoProvider, WithGroupStateStorage, WithIdentityProvider}, group::CommitOutput, identity::{SigningIdentity, basic::BasicIdentityProvider}};
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
    let credential = BasicCredential::new(username.as_bytes().to_vec());

    let (private_key, public_key) = RustCryptoProvider::new()
        .cipher_suite_provider(CIPHER_SUITE)
        .expect("cipher suite provider not found")
        .signature_key_generate()
        .expect("cannot generate signature keys");

    let identity = SigningIdentity::new(
        credential.into_credential(),
        public_key
    );

    Client::builder()
        .crypto_provider(RustCryptoProvider::new())
        .group_state_storage(MyGroupStorage::default()) // Use my custom group state storage
        .signing_identity(identity, private_key, CIPHER_SUITE)
        .identity_provider(BasicIdentityProvider::new())
        .build()
}

fn main() -> rootcause::Result<()> {
    let alice = make_client("alice");

    let mut alice_group = alice.create_group(
        ExtensionList::new(),
        ExtensionList::new(),
        None
    )?;

    let mut client_groups: Vec<(Client<_>, Group<_>)> = vec![];

    for i in 0..99 {
        let client = make_client(&format!("user{i}"));

        let key_pkg = client.generate_key_package_message(
            ExtensionList::new(),
            ExtensionList::new(),
            None
        )?;

        let proposal = alice_group.propose_add(key_pkg, vec![])?;

        let CommitOutput {
            commit_message,
            welcome_messages,
            ..
        } = alice_group.commit(vec![])?;

        alice_group.process_incoming_message(commit_message.clone())?;
        alice_group.write_to_storage()?;

        for (_, group) in &mut client_groups {
            group.process_incoming_message(proposal.clone())?;
            group.process_incoming_message(commit_message.clone())?;
            group.write_to_storage()?;
        }

        let (client_group, _) = client.join_group(
            None,
            &welcome_messages[0],
            None
        )?;

        client_groups.push((client, client_group));
    }

    println!("alice group size: {} bytes", alice.group_state_storage().serialized_size());

    let total_size_of_other_members: usize = client_groups
        .iter()
        .map(|(client, _)| client.group_state_storage().serialized_size())
        .sum();

    println!("total serialised size of other members: {total_size_of_other_members} bytes");

    Ok(())
}
