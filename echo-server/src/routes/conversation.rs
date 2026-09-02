use std::collections::HashMap;

use echo_types::{CryptoBox, Encrypted, Secret, SnowflakeID, SqlxMegolmMessage};
use rootcause::prelude::ResultExt;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use vodozemac::megolm::{MegolmMessage, SessionKey};

use crate::{error::{RouteError as E, RouteResult}, execute, fetch_all_as, ok, route, router::EchoContext};

#[derive(Clone, Copy, Debug, Deserialize, Error, Serialize)]
pub enum ConversationRouteError {
    #[error("conversation not found")]
    ConversationNotFound
}

#[route("conversations.messages.inbox")]
pub async fn manage_user_inbox(ctx: &mut EchoContext) -> RouteResult<()> {
    let user = ctx.user.unwrap();

    let per_page: i64 = 50;

    let stmt = "
        SELECT
            m.id AS message_id,
            gsk.blob AS session_key,
            omk.blob AS message_key
        FROM outgoing_message_keys omk
        INNER JOIN messages m
            ON omk.message_id = m.id
        INNER JOIN group_session_keys gsk
            ON gsk.sender_id = m.author_id
            AND gsk.recipient_id = omk.recipient_id
        WHERE gsk.recipient_id = $1
        LIMIT $2
        OFFSET $3
    ";

    let mut offset: i64 = 0;

    loop {
        let rows: Vec<(SnowflakeID, CryptoBox<SessionKey>, SqlxMegolmMessage)> = fetch_all_as!(
            &ctx.pool,
            stmt,
            user,
            per_page,
            offset
        );

        let rows: Vec<(_, _, MegolmMessage)> = rows
            .into_iter()
            .map(|(id, key, msg)| (id, key, msg.into()))
            .collect();

        println!("sending {} new keys to decrypt", rows.len());

        ctx.stream.send(&ok!(&rows)).await?;

        if rows.is_empty() {
            break;
        }

        println!("waiting on the keys to come back");

        let keys: HashMap<SnowflakeID, Encrypted<Secret>> = ctx.stream.receive().await?;

        println!("got the keys back!");

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
