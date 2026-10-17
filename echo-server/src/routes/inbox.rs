use std::collections::HashMap;

use echo_types::{Encrypted, OlmPreKeyMessage, OlmPublicKey, Secret, SnowflakeID, SqlxOlmMessage};
use rootcause::prelude::ResultExt;
use serde::{Deserialize, Serialize};
use vodozemac::{Curve25519PublicKey, olm::{AccountPickle, OlmMessage, PreKeyMessage, SessionPickle}};

use crate::{error::{RouteError as E, RouteResult}, execute, fetch_all_as, ok, route, router::EchoContext};

/// Material for an unestablished DM session.
///
/// DM sessions are established in a round-trip, where someone
/// sends a friend request containing the OTK for the Olm
/// session. The person accepting this must then create the
/// session and send back their copy of the session and a
/// [`PreKeyMessage`] for the original sender to construct
/// their own [`Session`].
///
/// [`Session`]: vodozemac::olm::Session
#[derive(Deserialize, Serialize)]
pub struct UnestablishedDmSession {
    pub user_olm_public_key: Curve25519PublicKey,
    pub pre_key_message: PreKeyMessage
}

#[route("inbox.dm.sessions.establish")]
pub async fn establish_pending_dm_sessions(ctx: &mut EchoContext) -> RouteResult<()> {
    let user = ctx.user.unwrap();

    let mut last_user_id = SnowflakeID::MAX;
    let per_page: i64 = 50;

    let stmt = "
        SELECT
            pdms.other,
            u.olm_public_key,
            pdms.pre_key_msg
        FROM pending_dm_sessions pdms
        INNER JOIN users u ON pdms.other = u.id
        WHERE pdms.waiting_on = $1
        AND pdms.other < $2
        ORDER BY pdms.other DESC
        LIMIT $3
    ";

    loop {
        let rows: Vec<(SnowflakeID, OlmPublicKey, OlmPreKeyMessage)> = fetch_all_as!(
            &ctx.pool,
            stmt,
            user,
            last_user_id,
            per_page
        );

        if let Some(&(user_id, ..)) = rows.last() {
            last_user_id = user_id;
        }

        let entries: HashMap<SnowflakeID, UnestablishedDmSession> = rows
            .into_iter()
            .map(|(id, pubkey, prekey)| (id, UnestablishedDmSession {
                user_olm_public_key: pubkey.into(),
                pre_key_message: prekey.into()
            }))
            .collect();

        ctx.stream.send(ok!(&entries)).await?;

        if entries.is_empty() {
            break;
        }

        let mut established_sessions: HashMap<SnowflakeID, Encrypted<SessionPickle>> = ctx.stream.receive().await?;

        established_sessions.retain(|id, _| entries.contains_key(id));

        let latest_account_state: Encrypted<AccountPickle> = ctx.stream.receive().await?;

        let mut tx = ctx
            .pool
            .begin()
            .await
            .context(E::Database)?;

        for (other, session) in established_sessions {
            execute!(
                &mut *tx,
                "DELETE FROM pending_dm_sessions WHERE waiting_on = $1 AND other = $2",
                user,
                other
            );

            execute!(
                &mut *tx,
                "INSERT INTO dm_sessions (owner, other, blob) VALUES ($1, $2, $3)",
                user,
                other,
                session
            );
        }

        execute!(
            &mut *tx,
            "UPDATE users SET olm_account = $2 WHERE id = $1",
            user,
            latest_account_state
        );

        tx.commit().await.context(E::Database)?;
    }

    Ok(())
}

#[route("inbox.dm.messages.unread")]
pub async fn process_unread_dm_messages(ctx: &mut EchoContext) -> RouteResult<()> {
    let user = ctx.user.unwrap();

    let mut last_message_id = SnowflakeID::MAX;
    let per_page: i64 = 50;

    let stmt = "
        SELECT
            msg.id,
            msg.sender,
            umsg.blob
        FROM unread_dm_messages umsg
        INNER JOIN dm_messages msg ON msg.id = umsg.message_id
        WHERE umsg.waiting_on = $1
        AND msg.id < $2
        ORDER BY msg.id DESC
        LIMIT $3
    ";

    loop {
        let rows: Vec<(
            SnowflakeID,
            SnowflakeID,
            SqlxOlmMessage
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

        let entries: HashMap<SnowflakeID, (SnowflakeID, OlmMessage)> = rows
            .into_iter()
            .map(|(id, author_id, olm)| (id, (author_id, olm.into())))
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
