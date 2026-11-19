use std::{str::FromStr, sync::Arc};

use echo_client::client::Client;
use echo_server::{router::EchoRouter, runner::run};
use echo_types::Friend;
use pgtemp::PgTempDB;
use rcgen::{CertifiedKey, generate_simple_self_signed};
use rootcause::Result;
use rustls_pki_types::{CertificateDer, PrivatePkcs8KeyDer, pem::PemObject};
use sqlx::{Executor, postgres::{PgConnectOptions, PgPoolOptions}};

async fn run_server() -> Result<()> {
    let temp = PgTempDB::from_builder(
        PgTempDB::builder()
            .with_bin_path("/usr/lib/postgresql/18/bin")
    );

    dbg!(temp.connection_string());

    let options = PgConnectOptions::from_str(&temp.connection_uri())?
        .statement_cache_capacity(0);

    // Open a pool of connections to the database.
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect_with(options)
        .await?;

    {
        let mut conn = pool.acquire().await?;

        let query = include_str!("../../SCHEMA.sql");

        // pgtemp opens a blank database, so all our tables need to be created.
        conn.execute(query).await?;
    }

    // Create a basic TLS certificate for testing purposes.
    // Typically, these would be loaded from files on disk.
    let CertifiedKey { cert, signing_key } = generate_simple_self_signed(vec![
        "localhost".to_string()
    ]).unwrap();

    let cert = CertificateDer::from(cert.der().to_vec());

    let key = PrivatePkcs8KeyDer::from_pem_slice(signing_key.serialize_pem().as_bytes())?;

    let asset_storage_path = "/tmp/asset-storage";

    if std::fs::exists(asset_storage_path)? {
        std::fs::remove_dir_all(asset_storage_path)?;
    }

    println!("starting server");

    // Start the server up
    tokio::spawn(run(
        "127.0.0.1:4433",
        vec![cert.clone()],
        key.into(),
        10,
        Arc::new(EchoRouter::new()),
        pool,
        asset_storage_path
    ));

    Ok(())
}

const DEFAULT_PASSWORD: &str = "password";

#[tokio::main]
async fn main() -> Result<()> {
    run_server().await?;

    let alice = Client::create_account(
        "alice",
        DEFAULT_PASSWORD,
        ("127.0.0.1", 4433)
    ).await?;

    let bob = Client::create_account(
        "bob",
        DEFAULT_PASSWORD,
        ("127.0.0.1", 4433)
    ).await?;

    alice.send_friend_request_to(bob.user_id()).await?;

    bob.accept_friend_request_from(alice.user_id()).await?;

    let friends: Vec<Friend> = alice.get_friends().await?;

    assert!(
        friends[0].user_id == bob.user_id(),
        "bob was not alice's friend"
    );

    let conversation_id = friends[0].conversation_id;

    alice.send_message(conversation_id, "hello bob", vec![], None).await?;

    let mut history = bob.get_conversation_history(conversation_id, None, None, 100).await;

    loop {
        let messages = history.fetch_next().await?;

        if messages.is_empty() {
            break;
        }

        for (message, secret) in messages {
            let Ok(content) = secret.decrypt(&message.body) else {
                continue;
            };

            let fetched = alice.fetch_user(message.author).await?;

            let username = if let Some(user) = &fetched {
                user.name.as_str()
            }
            else {
                "<unknown user>"
            };

            println!("{username}: {content}");
        }
    }

    Ok(())
}
