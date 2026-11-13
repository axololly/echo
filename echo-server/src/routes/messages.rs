use std::collections::HashMap;

use chrono::{DateTime, Utc};
use echo_server_derive::route;
use echo_types::{__convert_encrypted_to_crypto_box, BoxPublicKey, Compressable, Compressed, CryptoBox, Encrypted, Message, MessageBody, SNOWFLAKE_GEN, Secret, SnowflakeID, SqlxMegolmMessage};
use rootcause::{bail, option_ext::OptionExt, prelude::ResultExt};
use serde::{Deserialize, Serialize};
use sqlx::{QueryBuilder, prelude::FromRow};
use thiserror::Error;
use vodozemac::megolm::{GroupSessionPickle, MegolmMessage, SessionKey};

use crate::{error::{RouteError as E, RouteResult}, events::{Event, dispatch_event_for_conversation}, execute, exists, fetch_all_as, fetch_all_scalar, fetch_one_as, fetch_one_scalar, fetch_opt_as, fetch_opt_scalar, ok, router::EchoContext};

#[derive(Clone, Copy, Debug, Deserialize, Error, Serialize)]
pub enum MessagesRouteError {
    #[error("conversation not found")]
    ConversationNotFound,

    #[error("session not found")]
    SessionNotFound,

    #[error("message not found")]
    MessageNotFound,

    #[error("too many pinned messages")]
    TooManyPinnedMessages
}

use MessagesRouteError as M;

async fn is_part_of_conversation(
    ctx: &mut EchoContext,
    conversation_id: SnowflakeID
) -> RouteResult<bool> {
    let is_member = exists!(
        &ctx.pool,
        "SELECT 1 FROM conversation_members WHERE conversation_id = $1 AND user_id = $2",
        conversation_id,
        ctx.user.unwrap()
    );

    Ok(is_member)
}

/// A single conversation member's session,
/// packaging their outbound session and
/// the inbound sessions of all other members.
#[derive(Deserialize, Serialize)]
pub struct EncryptedChatSession {
    pub outbound: Encrypted<GroupSessionPickle>,
    pub inbounds: HashMap<SnowflakeID, CryptoBox<SessionKey>>
}

#[route("messages.sessions.get")]
pub async fn get_latest_conversation_session(ctx: &mut EchoContext) -> RouteResult<EncryptedChatSession> {
    let conversation_id: SnowflakeID = ctx.stream.receive().await?;

    if !is_part_of_conversation(ctx, conversation_id).await? {
        bail!(E::Messages(M::ConversationNotFound));
    }

    let user_id = ctx.user.unwrap();

    let stmt = "
        SELECT
            csk.receiver,
            csk.blob
        FROM conversation_session_keys csk
        INNER JOIN conversations c
            ON c.id = csk.conversation_id
            AND c.epoch = csk.epoch
        WHERE c.id = $1
        AND csk.sender = $2
    ";

    let rows: Vec<(SnowflakeID, Encrypted<GroupSessionPickle>)> = fetch_all_as!(
        &ctx.pool,
        stmt,
        conversation_id,
        user_id
    );

    let mut outbound = None;

    let mut inbounds = HashMap::new();

    for (receiver, enc) in rows {
        if receiver == user_id {
            outbound = Some(enc);
        }
        else {
            let session_key = __convert_encrypted_to_crypto_box(enc)
                .cast::<SessionKey>();

            inbounds.insert(receiver, session_key);
        }
    }

    let outbound = outbound
        .context(E::Messages(M::ConversationNotFound))?;

    let session = EncryptedChatSession {
        outbound,
        inbounds
    };

    Ok(session)
}

#[route("messages.sessions.ensure")]
pub async fn ensure_latest_conversation_session(ctx: &mut EchoContext) -> RouteResult<()> {
    let user_id = ctx.user.unwrap();

    let conversation_id: SnowflakeID = ctx.stream.receive().await?;

    let maybe_epoch: Option<i64> = fetch_opt_scalar!(
        &ctx.pool,
        "SELECT epoch FROM conversations WHERE id = $1",
        conversation_id
    );

    let Some(epoch) = maybe_epoch else {
        bail!(E::Messages(M::ConversationNotFound));
    };

    let stmt = "
        SELECT receiver
        FROM conversation_session_keys
        WHERE conversation_id = $1
        AND sender = $2
        AND epoch = $3
    ";

    let other_members: Vec<SnowflakeID> = fetch_all_scalar!(
        &ctx.pool,
        stmt,
        conversation_id,
        user_id,
        epoch
    );

    if !other_members.is_empty() {
        ctx.stream.send(ok!(false)).await?;

        return Ok(());
    }

    ctx.stream.send(ok!(true)).await?;

    let stmt = "
        SELECT
            cm.user_id,
            upk.box_public_key
        FROM conversation_members cm
        INNER JOIN users_public_keys upk
            ON upk.user_id = cm.user_id
        WHERE cm.conversation_id = $1
        AND cm.user_id != $2
    ";

    let raw_other_members: Vec<(SnowflakeID, BoxPublicKey)> = fetch_all_as!(
        &ctx.pool,
        stmt,
        conversation_id,
        user_id
    );

    let mut other_members: HashMap<SnowflakeID, BoxPublicKey> = raw_other_members
        .into_iter()
        .collect();

    ctx.stream.send(ok!(other_members)).await?;

    let session: EncryptedChatSession = ctx.stream.receive().await?;

    other_members.retain(|id, _| !session.inbounds.contains_key(id));

    if !other_members.is_empty() {
        bail!(E::InvalidData);
    }

    let mut tx = ctx
        .pool
        .begin()
        .await
        .context(E::Database)?;

    let stmt = "
        INSERT INTO conversation_session_keys (
            conversation_id,
            epoch,
            sender,
            receiver,
            blob
        ) VALUES ($1, $2, $3, $4, $5)
    ";

    execute!(
        &mut *tx,
        stmt,
        conversation_id,
        epoch,
        user_id,
        user_id,
        session.outbound
    );

    for (member_id, session_key) in session.inbounds {
        execute!(
            &mut *tx,
            stmt,
            conversation_id,
            epoch,
            user_id,
            member_id,
            session_key
        );
    }

    tx.commit().await.context(E::Database)?;

    Ok(())
}

/// Data necessary for sending a message somewhere.
///
/// This requires a Megolm session to have been uploaded to the
/// server prior to accessing this route.
#[derive(Deserialize, Serialize)]
pub struct SendMessageData {
    pub conversation_id: SnowflakeID,
    pub replied_to: Option<SnowflakeID>,
    pub message_body: Encrypted<MessageBody>,
    pub key_for_author: Encrypted<Secret>,
    pub key_for_others: MegolmMessage
}

#[route("messages.send")]
pub async fn send_message(ctx: &mut EchoContext) -> RouteResult<Message> {
    let author_id = ctx.user.unwrap();

    let SendMessageData {
        conversation_id,
        replied_to,
        message_body,
        key_for_author,
        key_for_others
    } = ctx.stream.receive_capped(4096).await?;

    if !is_part_of_conversation(ctx, conversation_id).await? {
        bail!(E::Messages(M::ConversationNotFound));
    }

    let epoch: i64 = fetch_one_scalar!(
        &ctx.pool,
        "SELECT epoch FROM conversations WHERE id = $1",
        conversation_id
    );

    let stmt = "
        SELECT 1 FROM conversation_session_keys
        WHERE conversation_id = $1
        AND epoch = $2
        AND sender = $3
    ";

    let has_session = exists!(
        &ctx.pool,
        stmt,
        conversation_id,
        epoch,
        author_id
    );

    if !has_session {
        bail!(E::Messages(M::SessionNotFound));
    }

    let message_id = SNOWFLAKE_GEN.next();

    let mut tx = ctx
        .pool
        .begin()
        .await
        .context(E::Database)?;

    let stmt = "
        INSERT INTO messages (
            id,
            conversation_id,
            parent_id,
            author,
            blob
        ) VALUES ($1, $2, $3, $4, $5)
    ";

    execute!(
        &mut *tx,
        stmt,
        message_id,
        conversation_id,
        replied_to,
        author_id,
        &message_body
    );

    let stmt = "
        INSERT INTO message_decryption_keys (
            message_id,
            user_id,
            blob
        ) VALUES ($1, $2, $3)
    ";

    execute!(
        &mut *tx,
        stmt,
        message_id,
        author_id,
        key_for_author
    );

    let stmt = "
        INSERT INTO pending_message_keys (
            message_id,
            epoch,
            blob
        ) VALUES ($1, $2, $3)
    ";

    execute!(
        &mut *tx,
        stmt,
        message_id,
        epoch,
        SqlxMegolmMessage::from(key_for_others)
    );

    tx.commit().await.context(E::Database)?;

    dispatch_event_for_conversation(
        ctx,
        conversation_id,
        Event::NewMessageReceived {
            conversation_id,
            message_id,
            author_id
        }
    ).await?;

    Ok(Message {
        id: message_id,
        conversation_id,
        replied_to,
        author: author_id,
        body: message_body,
        sent_at: Utc::now(),
        pinned: false
    })
}

/// Temporal parameters for fetching messages.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub enum MessageHistoryParams {
    Before(DateTime<Utc>),
    After(DateTime<Utc>),
    Between(DateTime<Utc>, DateTime<Utc>),
    Latest
}

/// Data related to getting a list of messages from a group.
///
/// The limit is capped at 100.
#[derive(Deserialize, Serialize)]
pub struct GetMessageHistoryData {
    pub conversation_id: SnowflakeID,
    pub params: MessageHistoryParams,
    pub limit: u8
}

#[derive(FromRow)]
struct MessageAndSecret {
    #[sqlx(flatten)]
    message: Message,
    secret: Encrypted<Secret>
}

type Messages = Vec<(Message, Encrypted<Secret>)>;

#[route("messages.history.get")]
pub async fn get_message_history(ctx: &mut EchoContext) -> RouteResult<Compressed<Messages>> {
    let user_id = ctx.user.unwrap();

    let GetMessageHistoryData {
        conversation_id,
        params,
        limit
    } = ctx.stream.receive().await?;

    if !is_part_of_conversation(ctx, conversation_id).await? {
        bail!(E::Messages(M::ConversationNotFound));
    }

    let base = r#"
        SELECT
            msg.*,
            mdk.blob AS "secret"
        FROM messages msg
        INNER JOIN message_decryption_keys mdk
            ON mdk.message_id = msg.id
    "#;

    let mut builder = QueryBuilder::new(base);

    builder
        .push("AND mdk.user_id = ")
        .push_bind(user_id);

    builder
        .push(" WHERE msg.conversation_id = ")
        .push_bind(conversation_id);

    use MessageHistoryParams as P;

    match params {
        P::Before(dt) => {
            builder
                .push(" AND msg.sent_at <")
                .push_bind(dt);
        },
        P::After(dt) => {
            builder
                .push(" AND msg.sent_at >")
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
                .push(" AND msg.sent_at < ")
                .push_bind(SnowflakeID::MAX.as_utc_date_time());
        }
    }

    builder
        .push(" ORDER BY msg.sent_at DESC LIMIT ")
        .push_bind(limit.min(100) as i64);

    let rows = builder
        .build_query_as()
        .fetch_all(&ctx.pool)
        .await
        .context(E::Database)?;

    let messages: Messages = rows
        .into_iter()
        .map(|MessageAndSecret { message, secret }| (message, secret))
        .collect();

    Ok(messages.compress())
}

/// Data relating to an unprocessed message.
///
/// It is the client's responsibility to handle these
/// and then reupload them.
#[derive(Deserialize, Serialize)]
pub struct UnprocessedMessage {
    pub box_public_key: BoxPublicKey,
    pub session_key: CryptoBox<SessionKey>,
    pub message_key: MegolmMessage
}

// TODO: allow the user to customise the page size

#[route("messages.unread.process")]
pub async fn process_unread_messages(ctx: &mut EchoContext) -> RouteResult<()> {
    let user_id = ctx.user.unwrap();
    let per_page: i64 = 50;

    let stmt = "
        SELECT
            msg.id AS message_id,
            upk.box_public_key AS author_public_key,
            csk.blob AS encrypted_session_key,
            pmk.blob AS megolm_key_message
        FROM pending_message_keys pmk
        INNER JOIN messages msg
            ON msg.id = pmk.message_id
        INNER JOIN conversation_session_keys csk
            ON csk.conversation_id = msg.conversation_id
            AND csk.epoch = pmk.epoch
            AND csk.sender = msg.author
        INNER JOIN users_public_keys upk
            ON upk.user_id = msg.author
        WHERE csk.receiver = $1
        AND msg.id < $2
        AND NOT EXISTS (
            SELECT 1 FROM message_decryption_keys mdk
            WHERE mdk.user_id = csk.receiver
            AND mdk.message_id = msg.id
        )
        ORDER BY msg.id DESC
        LIMIT $3
    ";

    let mut last_message_id = SnowflakeID::MAX;

    loop {
        let rows: Vec<(
            SnowflakeID,
            BoxPublicKey,
            CryptoBox<SessionKey>,
            SqlxMegolmMessage
        )> = fetch_all_as!(
            &ctx.pool,
            stmt,
            user_id,
            last_message_id,
            per_page
        );

        let latest_message_id = rows
            .last()
            .map(|&(id, ..)| id);

        let unprocessed_messages: HashMap<SnowflakeID, UnprocessedMessage> = rows
            .into_iter()
            .map(|(id, bpk, sk, msg)| (id, UnprocessedMessage {
                box_public_key: bpk,
                session_key: sk,
                message_key: msg.into()
            }))
            .collect();

        ctx.stream.send(ok!(unprocessed_messages)).await?;

        let Some(id) = latest_message_id else {
            break;
        };

        last_message_id = id;

        let mut processed_messages: HashMap<SnowflakeID, Encrypted<Secret>> = ctx.stream.receive().await?;

        processed_messages.retain(|id, _| unprocessed_messages.contains_key(id));

        let mut tx = ctx
            .pool
            .begin()
            .await
            .context(E::Database)?;

        for (message_id, message_secret) in processed_messages {
            execute!(
                &mut *tx,
                "INSERT INTO message_decryption_keys (user_id, message_id, blob) VALUES ($1, $2, $3)",
                user_id,
                message_id,
                message_secret
            );
        }

        tx.commit().await.context(E::Database)?;
    }

    Ok(())
}

/// Data necessary for pinning or unpinning a message.
///
/// If this request has no change on the pin status,
/// a notification is not broadcasted.
#[derive(Deserialize, Serialize)]
pub struct UpdateMessagePinData {
    pub message_id: SnowflakeID,
    pub new_pin_status: bool
}

#[route("messages.pin.update")]
pub async fn update_pin_status_on_message(ctx: &mut EchoContext) -> RouteResult<()> {
    let UpdateMessagePinData {
        message_id,
        new_pin_status
    } = ctx.stream.receive().await?;

    let conversation_id = fetch_opt_scalar!(
        &ctx.pool,
        "SELECT conversation_id FROM messages WHERE id = $1",
        message_id
    ).context(E::Messages(M::MessageNotFound))?;

    if !is_part_of_conversation(ctx, conversation_id).await? {
        bail!(E::Messages(M::MessageNotFound));
    }

    let pinned_messages: i64 = fetch_one_scalar!(
        &ctx.pool,
        "SELECT COUNT(id) FROM messages WHERE conversation_id = $1 AND pinned = TRUE",
        conversation_id
    );

    if pinned_messages >= 500 {
        bail!(E::Messages(M::TooManyPinnedMessages));
    }

    let stmt = "
        UPDATE messages
        SET pinned = $2
        WHERE id = $1
        RETURNING OLD.pinned";

    let old_pin_status: bool = fetch_one_scalar!(
        &ctx.pool,
        stmt,
        message_id,
        new_pin_status
    );

    if new_pin_status != old_pin_status {
        dispatch_event_for_conversation(ctx, conversation_id, Event::MessagePinStatusUpdated {
            message_id,
            pinned: true
        }).await?;
    }

    Ok(())
}

#[route("messages.get")]
pub async fn get_message(ctx: &mut EchoContext) -> RouteResult<Message> {
    let message_id: SnowflakeID = ctx.stream.receive().await?;

    let conversation_id = fetch_opt_scalar!(
        &ctx.pool,
        "SELECT conversation_id FROM messages WHERE id = $1",
        message_id
    ).context(E::Messages(M::MessageNotFound))?;

    if !is_part_of_conversation(ctx, conversation_id).await? {
        bail!(E::Messages(M::MessageNotFound));
    }

    let message: Message = fetch_one_as!(
        &ctx.pool,
        "SELECT * FROM messages WHERE id = $1",
        message_id
    );

    Ok(message)
}

/// Data relating to editing a message.
#[derive(Deserialize, Serialize)]
pub struct EditMessageData {
    pub message_id: SnowflakeID,
    pub new_body: Encrypted<MessageBody>
}

#[route("messages.edit")]
pub async fn edit_message(ctx: &mut EchoContext) -> RouteResult<()> {
    let user = ctx.user.unwrap();

    let EditMessageData {
        message_id,
        new_body
    } = ctx.stream.receive_capped(4096).await?;

    let (conversation_id, author) = fetch_opt_as!(
        &ctx.pool,
        "SELECT conversation_id, author FROM messages WHERE id = $1",
        message_id
    ).context(E::Messages(M::MessageNotFound))?;

    if user != author {
        bail!(E::Messages(M::MessageNotFound));
    }

    execute!(
        &ctx.pool,
        "UPDATE messages SET blob = $2 WHERE id = $1",
        message_id,
        new_body
    );

    dispatch_event_for_conversation(
        ctx,
        conversation_id,
        Event::MessageEdited {
            conversation_id,
            message_id
        }
    ).await?;

    Ok(())
}

#[route("messages.delete")]
pub async fn delete_message(ctx: &mut EchoContext) -> RouteResult<()> {
    let user = ctx.user.unwrap();

    let message_id: SnowflakeID = ctx.stream.receive().await?;

    let (conversation_id, author) = fetch_opt_as!(
        &ctx.pool,
        "SELECT conversation_id, author FROM messages WHERE id = $1",
        message_id
    ).context(E::Messages(M::MessageNotFound))?;

    if user != author {
        bail!(E::Messages(M::MessageNotFound));
    }

    execute!(
        &ctx.pool,
        "DELETE FROM messages WHERE id = $1",
        message_id
    );

    dispatch_event_for_conversation(
        ctx,
        conversation_id,
        Event::MessageDeleted {
            conversation_id,
            message_id
        }
    ).await?;

    Ok(())
}
