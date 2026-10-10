use echo_types::{Encrypted, Message, MessageBody, SNOWFLAKE_GEN, Secret, SnowflakeID, SqlxOlmMessage};
use rootcause::{bail, option_ext::OptionExt, prelude::ResultExt};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use vodozemac::olm::{OlmMessage, SessionPickle};

use crate::{error::{RouteError as E, RouteResult}, events::Event, execute, exists, fetch_opt_scalar, route, router::EchoContext};

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

    let maybe_session: Option<_> = fetch_opt_scalar!(
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
    pub message_body: Encrypted<MessageBody>,
    pub key_for_sender: Encrypted<Secret>,
    pub key_for_receiver: OlmMessage
}

#[route("dms.messages.send")]
pub async fn send_new_dm_message(ctx: &mut EchoContext) -> RouteResult<Message> {
    let sender = ctx.user.unwrap();

    let SendDmMessageData {
        receiver,
        message_body,
        key_for_sender,
        key_for_receiver
    } = ctx.stream.receive().await?;

    let sender_has_session = exists!(
        &ctx.pool,
        "SELECT 1 FROM dm_sessions WHERE owner = $1 AND other = $2",
        sender,
        receiver
    );

    if !sender_has_session {
        bail!(E::DirectMessage(DM::NoSessionFound));
    }

    let mut tx = ctx
        .pool
        .begin()
        .await
        .context(E::Database)?;

    let message_id = SNOWFLAKE_GEN.next();

    execute!(
        &mut *tx,
        "INSERT INTO dm_messages (id, sender, receiver, blob) VALUES ($1, $2, $3, $4)",
        message_id,
        sender,
        receiver,
        &message_body
    );

    execute!(
        &mut *tx,
        "INSERT INTO message_decryption_keys (message_id, user_id, blob) VALUES ($1, $2, $3)",
        message_id,
        sender,
        key_for_sender
    );

    execute!(
        &mut *tx,
        "INSERT INTO unread_dm_messages (message_id, waiting_on, blob) VALUES ($1, $2, $3)",
        message_id,
        receiver,
        SqlxOlmMessage::from(key_for_receiver)
    );

    tx.commit().await.context(E::Database)?;

    ctx
        .dispatcher
        .dispatch([receiver], Event::NewDirectMessageFrom(sender))
        .await;

    Ok(Message {
        id: message_id,
        author: sender,
        body: message_body
    })
}
