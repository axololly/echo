use echo_tasks::interval;
use rootcause::{Result, prelude::ResultExt};
use sqlx::PgPool;

use crate::execute;

/*
 * Based on the following two queries:
 *
 * SELECT pgmk.message_id
 * FROM pending_group_message_keys pgmk
 * INNER JOIN group_messages msg
 *   ON msg.id = pgmk.message_id
 * WHERE NOT EXISTS (
 *   SELECT 1 FROM group_members gm
 *   WHERE gm.group_id = msg.group_id
 *   AND NOT EXISTS (
 *     SELECT 1 FROM message_decryption_keys mdk
 *     WHERE mdk.message_id = pgmk.message_id
 *     AND mdk.user_id = gm.user_id
 *   )
 * );
 *
 * The innermost NOT EXISTS will abort if a member is missing
 * a decryption key for the central message. That produces a
 * list of users who still need the Megolm message.
 * The outermost NOT EXISTS ensures the list of people needing
 * the Megolm message is empty, therefore meaning the Megolm
 * message is no longer needed, and can be safely recycled.
 *
 * SELECT
 *   gsk.group_id,
 *   gsk.epoch,
 *   gsk.sender,
 *   gsk.receiver
 * FROM group_session_keys gsk
 * INNER JOIN group_messages msg
 *   ON msg.group_id = gsk.group_id
 *   AND msg.author = gsk.sender
 * WHERE NOT EXISTS (
 *   SELECT 1 FROM pending_group_message_keys pgmk
 *   WHERE pgmk.message_id = msg.id
 *   AND pgmk.epoch = gsk.epoch
 * );
*/

/// Context for every task to function properly.
#[derive(Clone)]
pub struct TaskContext {
    pub pool: PgPool
}

#[interval(hours = 6)]
#[rename(RemoveUnusedSessionData)]
pub async fn remove_unused_session_data(ctx: TaskContext) -> Result<()> {
    let clear_megolm_messages_stmt = "
        DELETE FROM pending_group_message_keys pgmk
        USING group_messages AS msg
        WHERE msg.id = pgmk.message_id
        AND NOT EXISTS (
            SELECT 1 FROM group_members gm
            WHERE gm.group_id = msg.group_id
            AND NOT EXISTS (
                SELECT 1 FROM message_decryption_keys mdk
                WHERE mdk.message_id = pgmk.message_id
                AND mdk.user_id = gm.user_id
            )
        )
    ";

    let clear_megolm_sessions_stmt = "
        DELETE FROM group_session_keys AS gsk
        WHERE EXISTS (
            SELECT 1
            FROM group_messages AS msg
            WHERE msg.group_id = gsk.group_id
              AND msg.author = gsk.sender
              AND NOT EXISTS (
                  SELECT 1
                  FROM pending_group_message_keys AS pgmk
                  WHERE pgmk.message_id = msg.id
                    AND pgmk.epoch = gsk.epoch
              )
        )
        AND NOT EXISTS (
            SELECT 1 FROM groups
            WHERE groups.id = gsk.group_id
              AND groups.epoch = gsk.epoch
        )
    ";

    let mut tx = ctx
        .pool
        .begin()
        .await
        .attach("while trying to acquire transaction")?;

    execute!(
        &mut *tx,
        clear_megolm_messages_stmt
    );

    execute!(
        &mut *tx,
        clear_megolm_sessions_stmt
    );

    tx.commit().await.attach("while committing transaction")?;

    Ok(())
}

/// Begin running all background tasks in this module.
pub fn run_all_tasks(ctx: TaskContext) {
    RemoveUnusedSessionData::start(ctx.clone());
}
