use std::collections::HashMap;

use echo_types::{Encrypted, OlmPreKeyMessage, OlmPublicKey, SnowflakeID};
use rootcause::prelude::ResultExt;
use serde::{Deserialize, Serialize};
use vodozemac::{Curve25519PublicKey, olm::{AccountPickle, PreKeyMessage, SessionPickle}};

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

#[route("inbox.sessions.dm.establish")]
pub async fn establish_pending_dm_sessions(ctx: &mut EchoContext) -> RouteResult<()> {
    let user = ctx.user.unwrap();

    let mut offset: i64 = 0;
    let per_page: i64 = 50;

    let stmt = "
        SELECT
            pdms.other,
            u.olm_public_key,
            pdms.pre_key_msg
        FROM pending_dm_sessions pdms
        INNER JOIN users u ON pdms.other = u.id
        WHERE pdms.waiting_on = $1
        LIMIT $2
        OFFSET $3
    ";

    loop {
        let rows: Vec<(SnowflakeID, OlmPublicKey, OlmPreKeyMessage)> = fetch_all_as!(
            &ctx.pool,
            stmt,
            user,
            per_page,
            offset
        );

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
                "INSERT INTO dm_sessions (owner, other, session) VALUES ($1, $2, $3)",
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

        offset += per_page;
    }

    Ok(())
}
