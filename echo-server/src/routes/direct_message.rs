use chrono::Utc;
use echo_types::{Encrypted, Message, MessageBody, MessageHistoryParams, SNOWFLAKE_GEN, Secret, SnowflakeID, SqlxOlmMessage};
use rootcause::{bail, option_ext::OptionExt, prelude::ResultExt};
use serde::{Deserialize, Serialize};
use sqlx::QueryBuilder;
use thiserror::Error;
use vodozemac::olm::{OlmMessage, SessionPickle};

use crate::{error::{RouteError as E, RouteResult}, events::Event, execute, exists, fetch_all_as, fetch_opt_scalar, route, router::EchoContext};

/// An error related to direct messaging.
#[derive(Clone, Copy, Debug, Deserialize, Error, Serialize)]
pub enum DirectMessageRouteError {
    #[error("sender has no Olm session with the receiver")]
    NoSessionFound
}

use DirectMessageRouteError as DM;

#[route("dms.sessions.get")]
pub async fn get_dm_session(ctx: &mut EchoContext) -> RouteResult<Encrypted<SessionPickle>> {
    let sender = ctx.user.unwrap();

    let receiver: SnowflakeID = ctx.stream.receive().await?;

    let maybe_session = fetch_opt_scalar!(
        &ctx.pool,
        "SELECT blob FROM dm_sessions WHERE owner = $1 AND other = $2",
        sender,
        receiver
    );

    maybe_session
        .context(E::DirectMessage(DM::NoSessionFound))
}

/// Data necessary for sending a direct message to another user.
///
/// This requires an Olm session to have been uploaded to the
/// server prior to accessing this route.
#[derive(Deserialize, Serialize)]
pub struct SendDmMessageData {
    pub receiver: SnowflakeID,
    pub replied_to: Option<SnowflakeID>,
    pub message_body: Encrypted<MessageBody>,
    pub key_for_sender: Encrypted<Secret>,
    pub key_for_receiver: OlmMessage
}

#[route("dms.messages.send")]
pub async fn send_new_dm_message(ctx: &mut EchoContext) -> RouteResult<Message> {
    let sender = ctx.user.unwrap();

    // Disallow message data above 4KB to be received
    let SendDmMessageData {
        receiver,
        replied_to,
        message_body,
        key_for_sender,
        key_for_receiver
    } = ctx.stream.receive_capped(4096).await?;

    dbg!(ctx.pool.size(), ctx.pool.num_idle());

    let sender_has_session = exists!(
        &ctx.pool,
        "SELECT 1 FROM dm_sessions WHERE owner = $1 AND other = $2",
        sender,
        receiver
    );

    println!("1");

    if !sender_has_session {
        bail!(E::DirectMessage(DM::NoSessionFound));
    }

    println!("2");

    let mut tx = ctx
        .pool
        .begin()
        .await
        .context(E::Database)?;

    println!("3");

    let message_id = SNOWFLAKE_GEN.next();

    execute!(
        &mut *tx,
        "INSERT INTO dm_messages (id, parent_id, sender, receiver, blob) VALUES ($1, $2, $3, $4, $5)",
        message_id,
        replied_to,
        sender,
        receiver,
        &message_body
    );

    println!("4");

    execute!(
        &mut *tx,
        "INSERT INTO message_decryption_keys (message_id, user_id, blob) VALUES ($1, $2, $3)",
        message_id,
        sender,
        key_for_sender
    );

    println!("5");

    execute!(
        &mut *tx,
        "INSERT INTO pending_dm_message_keys (message_id, waiting_on, blob) VALUES ($1, $2, $3)",
        message_id,
        receiver,
        SqlxOlmMessage::from(key_for_receiver)
    );

    println!("6");

    tx.commit().await.context(E::Database)?;

    println!("7");

    ctx
        .dispatcher
        .dispatch([receiver], Event::NewDirectMessageFrom(sender))
        .await;

    Ok(Message {
        id: message_id,
        replied_to,
        author: sender,
        body: message_body,
        sent_at: Utc::now()
    })
}

/// Data related to getting a list of messages from a group.
///
/// The limit is capped at 100.
#[derive(Deserialize, Serialize)]
pub struct GetDmMessageHistoryData {
    pub other: SnowflakeID,
    pub params: MessageHistoryParams,
    pub limit: u8
}

#[route("dms.messages.history.get")]
pub async fn get_dm_message_history(ctx: &mut EchoContext) -> RouteResult<Vec<(Message, Encrypted<Secret>)>> {
    let user_id = ctx.user.unwrap();

    let GetDmMessageHistoryData {
        other,
        params,
        limit
    } = ctx.stream.receive().await?;

    let base = "
        SELECT
            msg.id,
            msg.parent_id,
            msg.sender,
            msg.blob,
            msg.sent_at,
            mdk.blob
        FROM dm_messages msg
        INNER JOIN message_decryption_keys mdk
            ON mdk.message_id = msg.id
    ";

    let mut builder = QueryBuilder::new(base);

    builder
        .push("AND mdk.user_id = ")
        .push_bind(user_id)
        .push(format!("
            WHERE (msg.sender = {user_id} AND msg.receiver = {other}
            OR msg.sender = {other} AND msg.receiver = {user_id})
        "));

    use MessageHistoryParams as P;

    match params {
        P::Before(dt) => {
            builder
                .push(" AND msg.sent_at < ")
                .push_bind(dt);
        },
        P::After(dt) => {
            builder
                .push("AND msg.sent_at > ")
                .push_bind(dt);
        },
        P::Between(start, end) => {
            if start > end {
                bail!(E::InvalidData);
            }

            builder
                .push(" AND msg.sent_at > ")
                .push_bind(start)
                .push(" AND msg.sent_at < ")
                .push_bind(end);
        },
        P::Latest => {
            builder
                .push(" AND msg.sent < ")
                .push_bind(SnowflakeID::MAX.as_utc_date_time());
        }
    }

    builder
        .push(" LIMIT ")
        .push_bind(limit.min(100) as i8);

    let rows: Vec<_> = fetch_all_as!(
        &ctx.pool,
        builder.into_sql()
    );

    let mut messages = vec![];

    for (id, replied_to, author, body, sent_at, secret) in rows {
        let message = Message {
            id,
            replied_to,
            author,
            body,
            sent_at
        };

        messages.push((message, secret));
    }

    Ok(messages)
}
