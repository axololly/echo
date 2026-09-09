use std::collections::HashMap;

use echo_akd::EchoLookupProof;
use echo_types::{CryptoBox, Encrypted, Secret, SnowflakeID, SqlxMegolmMessage};
use rootcause::prelude::ResultExt;
use serde::{Deserialize, Serialize};
use vodozemac::megolm::{MegolmMessage, SessionKey};

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

        let keys: HashMap<SnowflakeID, Encrypted<Secret>> = ctx.stream.receive().await?;

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

#[route("inbox.dms")]
pub async fn manage_dm_message_inbox(ctx: &mut EchoContext) -> RouteResult<()> {
    let stmt = "
        SELECT
            dms.blob AS session,
            omk
        FROM dm_sessions dms
        INNER JOIN outgoing_dm_message_keys omk ON omk.
    ";

    Ok(())
}
