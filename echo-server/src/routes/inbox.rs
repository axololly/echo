use std::collections::{HashMap, HashSet};

use echo_akd::EchoLookupProof;
use echo_types::{CryptoBox, Encrypted, Message, MessageBody, Secret, SnowflakeID, SqlxMegolmMessage, SqlxOlmMessage};
use rootcause::prelude::ResultExt;
use serde::{Deserialize, Serialize};
use vodozemac::{megolm::{MegolmMessage, SessionKey}, olm::{OlmMessage, SessionPickle}};

use crate::{error::{RouteError as E, RouteResult}, fetch_all_as, execute, ok, route, router::EchoContext};

#[derive(Deserialize, Serialize)]
pub struct GroupInboxEntry {
    pub message_id: SnowflakeID,
    pub author_id: SnowflakeID,
    pub lookup: EchoLookupProof,
    pub session_key: CryptoBox<SessionKey>,
    pub megolm_message: MegolmMessage
}

#[route("inbox.groups")]
pub async fn manage_group_message_inbox(ctx: &mut EchoContext) -> RouteResult<()> {
    let user = ctx.user.unwrap();

    let per_page: i64 = 50;

    let stmt = "
        SELECT
            m.id,
            gsk.sender_id,
            gsk.blob,
            omk.blob
        FROM outgoing_message_keys omk
        INNER JOIN messages m
            ON omk.message_id = m.id
        INNER JOIN group_session_keys gsk
            ON gsk.sender_id = m.author_id
            AND gsk.recipient_id = omk.recipient_id
        WHERE gsk.recipient_id = $1
        AND gsk.sender_id != $1
        LIMIT $2
        OFFSET $3
    ";

    let mut offset: i64 = 0;

    loop {
        let rows: Vec<(SnowflakeID, SnowflakeID, CryptoBox<SessionKey>, SqlxMegolmMessage)> = fetch_all_as!(
            &ctx.pool,
            stmt,
            user,
            per_page,
            offset
        );

        let message_ids: HashSet<SnowflakeID> = rows
            .iter()
            .map(|&(id, ..)| id)
            .collect();

        let mut entries: Vec<GroupInboxEntry> = vec![];

        for (message_id, author_id, session_key, megolm_msg) in rows {
            let lookup = ctx
                .akd
                .single_lookup(&author_id)
                .await
                .context(E::Database)?;

            entries.push(GroupInboxEntry {
                message_id,
                author_id,
                lookup,
                session_key,
                megolm_message: megolm_msg.into()
            });
        }

        ctx.stream.send(&ok!(&entries)).await?;

        if entries.is_empty() {
            break;
        }

        let mut keys: HashMap<SnowflakeID, Encrypted<Secret>> = ctx.stream.receive().await?;

        keys.retain(|id, _| message_ids.contains(id));

        let mut tx = ctx
            .pool
            .begin()
            .await
            .context(E::Database)?;

        for (message_id, enc) in keys {
            let stmt = "
                DELETE FROM outgoing_message_keys
                WHERE recipient_id = $1
                AND message_id = $2
            ";

            execute!(&mut *tx, stmt, user, message_id);

            let stmt = "
                INSERT INTO message_decryption_keys (
                    user_id,
                    message_id,
                    blob
                ) VALUES ($1, $2, $3)
            ";

            execute!(&mut *tx, stmt, user, message_id, enc);
        }

        tx.commit().await.context(E::Database)?;

        offset += per_page;
    }

    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DmInboxEntry {
    pub message_id: SnowflakeID,
    pub author_id: SnowflakeID,
    pub olm_message: OlmMessage
}

#[route("inbox.dms")]
pub async fn manage_dm_message_inbox(ctx: &mut EchoContext) -> RouteResult<()> {
    let user = ctx.user.unwrap();

    let stmt = "
        SELECT
            initiator,
            pre_key_msg
        FROM pending_dm_sessions
        WHERE waiting_on = $1
    ";

    let rows: Vec<(SnowflakeID, SqlxOlmMessage)> = fetch_all_as!(
        &ctx.pool,
        stmt,
        user
    );

    let pending_sessions: HashMap<SnowflakeID, OlmMessage> = rows
        .into_iter()
        .map(|(id, msg)| (id, msg.into()))
        .collect();

    ctx.stream.send(&ok!(pending_sessions)).await?;

    let mut encrypted_sessions: HashMap<SnowflakeID, Encrypted<SessionPickle>> = ctx
        .stream
        .receive()
        .await?;

    encrypted_sessions.retain(|id, _| pending_sessions.contains_key(id));

    let stmt = "
        SELECT
            dms.other_id AS sender_id,
            dms.blob AS session_blob
        FROM outgoing_dm_message_keys omk
        INNER JOIN dm_sessions dms
            ON dms.owner_id = omk.recipient_id
            AND dms.other_id = omk.sender_id
        WHERE omk.recipient_id = $1
        LIMIT $2
        OFFSET $3
    ";

    let raw_sessions: Vec<(
        SnowflakeID,
        Encrypted<SessionPickle>
    )> = fetch_all_as!(
        &ctx.pool,
        stmt,
        user
    );

    let sessions: HashMap<SnowflakeID, Encrypted<SessionPickle>> = raw_sessions
        .into_iter()
        .collect();

    ctx.stream.send(&ok!(sessions)).await?;

    let stmt = "
        SELECT
            msgs.id AS message_id,
            dms.sender_id AS sender_id
            omk.blob AS key_blob,
        FROM outgoing_dm_message_keys omk
        INNER JOIN dm_sessions dms
            ON omk.owner_id = dms.receipient_id
            AND omk.other_id = dms.sender_id
        INNER JOIN dm_messages msgs
            ON msgs.id = omk.message_id
        LIMIT $2
        OFFSET $3
    ";

    let per_page: i64 = 50;
    let mut offset: i64 = 0;

    loop {
        let rows: Vec<(
            SnowflakeID,
            SnowflakeID,
            OlmMessage
        )> = fetch_all_as!(
            &ctx.pool,
            stmt,
            user,
            per_page,
            offset
        );

        let entries = rows
            .into_iter()
            .map(|(message_id, author_id, olm_message)| DmInboxEntry {
                message_id,
                author_id,
                olm_message
            })
            .collect();

        ctx.stream.send(&ok!(entries)).await?;

        // TODO: receive and store

        offset += per_page;
    }

    Ok(())
}
