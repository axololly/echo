use std::{collections::HashMap, net::ToSocketAddrs, str::FromStr, sync::Arc};

use crypto_box::PublicKey;
use pgtemp::PgTempDB;
use quinn::{crypto::rustls::QuicClientConfig, rustls};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use rootcause::{Result, bail};
use rustls_pki_types::{CertificateDer, PrivatePkcs8KeyDer, pem::PemObject};
use echo_server::{error::RouteError, router::EchoRouter, routes::{CreateNewFriendRequestData, CreateNewGroupData, CreateNewUserData, EncryptedMegolmSession, SendGroupMessageData}, runner::run, stream::Stream};
use echo_types::{CryptoBox, Encrypted, Group, Message, MessageBody, PasswordProtected, Secret, SnowflakeID, User, UserSettings};
use sqlx::{Executor, postgres::{PgConnectOptions, PgPoolOptions}};
use vodozemac::{megolm::{GroupSession, InboundGroupSession, MegolmMessage, SessionConfig as MegolmConfig, SessionKey}, olm::Account};

async fn access_resource<T>(
    parent: &quinn::Connection,
    route: &str,
    mut f: impl AsyncFnMut(&mut Stream) -> Result<T>
) -> Result<T> {
    println!("-- trying to access resource {route:?} --");

    let mut stream = Stream::open_bi(parent).await?;

    stream.send(&route).await?;

    stream.receive::<RouteResult<()>>().await??;

    f(&mut stream).await
}

type RouteResult<T> = std::result::Result<T, RouteError>;

async fn create_account(parent: &quinn::Connection, username: &str) -> Result<(User, Account)> {
    access_resource(parent, "users.create", async |stream| {
        let secret = Secret::random();

        let olm_account = Account::new(); // TODO: use this to test out messaging

        let data = CreateNewUserData {
            username: username.to_string(),
            secret: PasswordProtected::new(&secret, "6767"),
            settings: secret.encrypt(&UserSettings {
                cache_secret_for: 0,
                logout_after: 0,
                enable_read_receipts: true,
                enable_typing_indicators: true
            }),
            signature_verifier: secret.into(),
            olm_account: secret.encrypt(&olm_account.pickle()),
            encryption_public_key: secret.into()
        };

        stream.send(&data).await?;

        let user: User = stream.receive::<RouteResult<_>>().await??;

        println!("ID of user {:?} is {}", user.name, user.id);

        Ok((user, olm_account))
    }).await
}

#[tokio::main]
async fn main() -> Result<()> {
    let temp = PgTempDB::from_builder(
        PgTempDB::builder()
            .with_bin_path("/usr/lib/postgresql/17/bin")
    );

    let options = PgConnectOptions::from_str(&temp.connection_uri())?
        .statement_cache_capacity(0);

    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect_with(options)
        .await?;

    {
        let mut conn = pool.acquire().await?;

        let query = include_str!("../../SCHEMA.sql");

        conn.execute(query).await?;
    }

    let CertifiedKey { cert, signing_key } = generate_simple_self_signed(vec![
        "localhost".to_string()
    ]).unwrap();

    let cert = CertificateDer::from(cert.der().to_vec());

    let key = PrivatePkcs8KeyDer::from_pem_slice(signing_key.serialize_pem().as_bytes())?;

    tokio::spawn(run(
        "localhost:4433",
        vec![cert.clone()],
        key.into(),
        10,
        Arc::new(EchoRouter::new().await),
        pool
    ));

    let into_socket_addr = |raw: &str| raw
        .to_socket_addrs()
        .expect("failed to resolve IP")
        .next()
        .expect("failed to resolve IP - none found");

    let local = into_socket_addr("localhost:10092");

    let mut root_store = rustls::RootCertStore::from_iter(
        webpki_roots::TLS_SERVER_ROOTS.iter().cloned()
    );

    root_store.add(cert)?;

    if root_store.is_empty() {
        bail!("no TLS server certificates");
    }

    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    client_crypto.alpn_protocols = vec![b"hq-29".to_vec()];

    let client_config = quinn::ClientConfig::new(
        Arc::new(
            QuicClientConfig::try_from(client_crypto)?
        )
    );

    let mut endpoint = quinn::Endpoint::client(local)?;

    endpoint.set_default_client_config(client_config);

    let parent = endpoint
        .connect(into_socket_addr("localhost:4433"), "localhost")?
        .await?;

    let (alice, mut alice_olm) = create_account(&parent, "alice").await?;
    let (bob, _) = create_account(&parent, "bob").await?;

    let alice_secret = alice.secret.unlock("6767")?;
    let alice_signed_id = alice_secret.sign(alice.id);

    let bob_secret = bob.secret.unlock("6767")?;
    let bob_signed_id = bob_secret.sign(bob.id);

    access_resource(&parent, "users.friends.requests.create", async |stream| {
        stream.send(&alice_signed_id).await?;

        alice_olm.generate_one_time_keys(1);

        let one_time_key = *alice_olm.one_time_keys().values().next().unwrap();

        alice_olm.mark_keys_as_published();

        stream.send(&CreateNewFriendRequestData {
            recipient: bob.id,
            one_time_key: one_time_key.into()
        }).await?;

        Ok(())
    }).await?;

    access_resource(&parent, "users.friends.requests.accept", async |stream| {
        stream.send(&bob_signed_id).await?;

        stream.send(&alice.id).await?;

        Ok(())
    }).await?;

    let group = access_resource(&parent, "groups.create", async |stream| {
        stream.send(&alice_signed_id).await?;

        stream.send(&CreateNewGroupData {
            name: "very cool group chat".to_string(),
            initial_members: vec![bob.id]
        }).await?;

        let group: Group = stream.receive::<RouteResult<_>>().await??;

        Ok(group)
    }).await?;

    println!("group ID: {}", group.id);

    let mut alice_group_session = access_resource(&parent, "groups.sessions.ensure", async |stream| {
        stream.send(&alice_signed_id).await?;

        stream.send(&group.id).await?;

        let needs_uploading: bool = stream.receive::<RouteResult<_>>().await??;

        assert!(needs_uploading);

        let keys: HashMap<SnowflakeID, PublicKey> = stream.receive::<RouteResult<_>>().await??;

        let group_session = GroupSession::new(MegolmConfig::version_1());

        let session_key = group_session.session_key();

        let inbounds = keys
            .into_iter()
            .map(|(id, key)| (id, alice_secret.box_for(&session_key, key)))
            .collect();

        let upload_data = EncryptedMegolmSession {
            outbound: alice_secret.encrypt(&group_session.pickle()),
            inbounds
        };

        stream.send(&upload_data).await?;

        Ok(group_session)
    }).await?;

    let alice_message = access_resource(&parent, "groups.messages.send", async |stream| {
        stream.send(&alice_signed_id).await?;

        let message_secret = Secret::random();

        let message_body = message_secret.encrypt(&MessageBody {
            content: "hello bob".to_string()
        });

        let message_key_for_others = alice_group_session.encrypt(message_secret);

        let message_key_for_self = alice_secret.encrypt(&message_secret);

        stream.send(&SendGroupMessageData {
            group_id: group.id,
            replied_to: None,
            message_body,
            message_key_for_others,
            message_key_for_self
        }).await?;

        let msg: Message = stream.receive::<RouteResult<_>>().await??;

        Ok(msg)
    }).await?;

    let (chloe, _) = create_account(&parent, "chloe").await?;

    let chloe_secret = chloe.secret.unlock("6767")?;
    let chloe_signed_id = chloe_secret.sign(chloe.id);

    access_resource(&parent, "groups.join", async |stream| {
        stream.send(&chloe_signed_id).await?;

        stream.send(&group.invite_code).await?;

        let new_group: Group = stream.receive::<RouteResult<_>>().await??;

        assert_eq!(new_group.id, group.id, "group IDs were not the same somehow");

        Ok(())
    }).await?;

    let mut chloe_group_session = access_resource(&parent, "groups.sessions.ensure", async |stream| {
        stream.send(&chloe_signed_id).await?;

        stream.send(&group.id).await?;

        let needs_uploading: bool = stream.receive::<RouteResult<_>>().await??;

        assert!(needs_uploading);

        let keys: HashMap<SnowflakeID, PublicKey> = stream.receive::<RouteResult<_>>().await??;

        let group_session = GroupSession::new(MegolmConfig::version_1());

        let session_key = group_session.session_key();

        let inbounds = keys
            .into_iter()
            .map(|(id, key)| (id, chloe_secret.box_for(&session_key, key)))
            .collect();

        let upload_data = EncryptedMegolmSession {
            outbound: chloe_secret.encrypt(&group_session.pickle()),
            inbounds
        };

        stream.send(&upload_data).await?;

        Ok(group_session)
    }).await?;

    let chloe_message = access_resource(&parent, "groups.messages.send", async |stream| {
        stream.send(&chloe_signed_id).await?;

        let message_secret = Secret::random();

        let message_body = message_secret.encrypt(&MessageBody {
            content: "hello everyone".to_string()
        });

        let message_key_for_others = chloe_group_session.encrypt(message_secret);

        let message_key_for_self = chloe_secret.encrypt(&message_secret);

        stream.send(&SendGroupMessageData {
            group_id: group.id,
            replied_to: None,
            message_body,
            message_key_for_others,
            message_key_for_self
        }).await?;

        let msg: Message = stream.receive::<RouteResult<_>>().await??;

        Ok(msg)
    }).await?;

    let bob_message_keys = access_resource(&parent, "conversations.messages.inbox", async |stream| {
        stream.send(&bob_signed_id).await?;

        let mut message_keys = HashMap::new();

        loop {
            let mut map: HashMap<SnowflakeID, Encrypted<Secret>> = HashMap::new();

            let rows: Vec<(SnowflakeID, PublicKey, CryptoBox<SessionKey>, MegolmMessage)> = stream.receive::<RouteResult<_>>().await?.unwrap();

            if rows.is_empty() {
                break;
            }

            for (message_id, public_key, session_key, key_message) in rows {
                let session_key = bob_secret.unbox_from(&session_key, public_key).unwrap();

                let mut inbound = InboundGroupSession::new(
                    &session_key,
                    MegolmConfig::version_1()
                );

                let dec = inbound.decrypt(&key_message)?;

                let message_key = Secret::try_from_bytes(&dec.plaintext)?;

                message_keys.insert(message_id, message_key);

                map.insert(message_id, alice_secret.encrypt(&message_key));
            }

            stream.send(&map).await?;
        }

        Ok(message_keys)
    }).await?;

    println!("alice said: {:?}", bob_message_keys[&alice_message.id].decrypt(&alice_message.body)?.content);
    println!("chloe said: {:?}", bob_message_keys[&chloe_message.id].decrypt(&chloe_message.body)?.content);

    Ok(())
}
