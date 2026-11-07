use std::collections::HashMap;

use echo_types::{BoxPublicKey, CryptoBox, Encrypted, Secret, SnowflakeID, SqlxMegolmMessage};
use rootcause::prelude::ResultExt;
use serde::{Deserialize, Serialize};
use vodozemac::megolm::{MegolmMessage, SessionKey};

use crate::{error::{RouteError as E, RouteResult}, execute, fetch_all_as, ok, route, router::EchoContext};

#[route("inbox.messages.dm.unread")]
pub async fn process_unread_dm_messages(ctx: &mut EchoContext) -> RouteResult<()> {
    let user = ctx.user.unwrap();

    let mut last_message_id = SnowflakeID::MAX;
    let per_page: i64 = 50;

    let stmt = "
        SELECT
            msg.id,
            msg.sender,
            pmk.blob
        FROM pending_dm_message_keys pmk
        INNER JOIN dm_messages msg
            ON msg.id = pmk.message_id
        WHERE pmk.waiting_on = $1
        AND msg.id < $2
        ORDER BY msg.id DESC
        LIMIT $3
    ";

    loop {
        let rows: Vec<(
            SnowflakeID,
            SnowflakeID,
            SqlxMegolmMessage
        )> = fetch_all_as!(
            &ctx.pool,
            stmt,
            user,
            last_message_id,
            per_page
        );

        if let Some(&(message_id, ..)) = rows.last() {
            last_message_id = message_id;
        }

        let entries: HashMap<SnowflakeID, (SnowflakeID, MegolmMessage)> = rows
            .into_iter()
            .map(|(id, author_id, megolm)| (id, (author_id, megolm.into())))
            .collect();

        ctx.stream.send(ok!(entries)).await?;

        if entries.is_empty() {
            break;
        }

        let mut resolved: HashMap<SnowflakeID, Encrypted<Secret>> = ctx.stream.receive().await?;

        resolved.retain(|id, _| entries.contains_key(id));

        let mut tx = ctx
            .pool
            .begin()
            .await
            .context(E::Database)?;

        for (message_id, message_key) in resolved {
            execute!(
                &mut *tx,
                "DELETE FROM pending_dm_message_keys WHERE message_id = $1 AND waiting_on = $2",
                message_id,
                user
            );

            execute!(
                &mut *tx,
                "INSERT INTO message_decryption_keys (message_id, user_id, blob) VALUES ($1, $2, $3)",
                message_id,
                user,
                message_key
            );
        }

        tx.commit().await.context(E::Database)?;
    }

    Ok(())
}

/// Data relating to an unprocessed group message.
///
/// It is the client's responsibility to handle these
/// and then reupload them.
#[derive(Deserialize, Serialize)]
pub struct UnprocessedGroupMessage {
    pub box_public_key: BoxPublicKey,
    pub session_key: CryptoBox<SessionKey>,
    pub message_key: MegolmMessage
}

#[route("inbox.messages.group.unread")]
pub async fn process_unread_group_messages(ctx: &mut EchoContext) -> RouteResult<()> {
    let user_id = ctx.user.unwrap();
    let per_page: i64 = 50;

    let stmt = "
        SELECT
            msg.id AS message_id,
            upk.box_public_key AS author_public_key,
            gsk.blob AS encrypted_session_key,
            pgmk.blob AS megolm_key_message
        FROM pending_group_message_keys pgmk
        INNER JOIN group_messages msg
            ON msg.id = pgmk.message_id
        INNER JOIN group_session_keys gsk
            ON gsk.group_id = msg.group_id
            AND gsk.epoch = pgmk.epoch
            AND gsk.sender = msg.author
        INNER JOIN users_public_keys upk
            ON upk.user_id = msg.author
        WHERE gsk.receiver = $1
        AND msg.id < $2
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

        let unprocessed_messages: HashMap<SnowflakeID, UnprocessedGroupMessage> = rows
            .into_iter()
            .map(|(id, bpk, sk, msg)| (id, UnprocessedGroupMessage {
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
