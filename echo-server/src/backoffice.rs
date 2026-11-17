use std::time::Duration;

use chrono::{DateTime, Utc};
use echo_tasks::interval;
use echo_types::SnowflakeID;
use rootcause::{Report, Result, prelude::ResultExt};
use sqlx::PgPool;
use tracing::error;

use crate::{execute, fetch_opt_as};

/// Context for every task to function properly.
#[derive(Clone)]
pub struct TaskContext {
    pub pool: PgPool
}

async fn error_handler(err: Report) {
    error!("Encountered error when running background task: {err:?}");
}

#[interval(hours = 6)]
#[rename(RemoveUnusedSessionData)]
#[on_error(error_handler)]
pub async fn remove_unused_session_data(ctx: TaskContext) -> Result<()> {
    let clear_megolm_messages_stmt = "
        DELETE FROM pending_message_keys pgmk
        USING messages AS msg
        WHERE msg.id = pgmk.message_id
        AND NOT EXISTS (
            SELECT 1 FROM conversation_members cm
            WHERE cm.conversation_id = msg.conversation_id
            AND cm.joined_at < msg.sent_at
            AND NOT EXISTS (
                SELECT 1 FROM message_decryption_keys mdk
                WHERE mdk.message_id = pgmk.message_id
                AND mdk.user_id = cm.user_id
            )
        )
    ";

    let clear_megolm_sessions_stmt = "
        DELETE FROM conversation_session_keys AS csk
        WHERE EXISTS (
            SELECT 1
            FROM messages AS msg
            WHERE msg.conversation_id = csk.conversation_id
              AND msg.author = csk.sender
              AND NOT EXISTS (
                  SELECT 1
                  FROM pending_message_keys AS pmk
                  WHERE pmk.message_id = msg.id
                    AND pmk.epoch = gsk.epoch
              )
        )
        AND NOT EXISTS (
            SELECT 1 FROM conversations c
            WHERE c.id = csk.conversation_id
              AND c.epoch = csk.epoch
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

#[interval(secs = 1)]
#[rename(DeleteDisappearingMessages)]
pub async fn delete_disappearing_messages(ctx: TaskContext) -> Result<()> {
    let stmt = "
        SELECT id, delete_at
        FROM messages
        ORDER BY delete_at ASC
        LIMIT 1
    ";

    let row: Option<(SnowflakeID, DateTime<Utc>)> = fetch_opt_as!(&ctx.pool, stmt);

    let Some((message_id, delete_at)) = row else {
        RUNNING_TASK.cancel();

        return Ok(());
    };

    let delta = delete_at - Utc::now();

    let secs = delta.num_seconds().max(0) as u64;
    let nanos = delta.subsec_nanos().max(0) as u32;

    tokio::time::sleep(Duration::new(secs, nanos)).await;

    execute!(
        &ctx.pool,
        "DELETE FROM messages WHERE id = $1",
        message_id
    );

    Ok(())
}

/// All currently running tasks in the application.
///
/// This provides an interface to start, stop or restart
/// the running tasks.
#[derive(Clone)]
pub struct RunningTasks {
    pub remove_unused_session_data: RemoveUnusedSessionData,
    pub delete_disappearing_messages: DeleteDisappearingMessages
}

/// Begin running all background tasks in this module.
pub fn run_all_tasks(ctx: TaskContext) -> RunningTasks {
    let remove_unused_session_data = RemoveUnusedSessionData::start(ctx.clone());
    let delete_disappearing_messages = DeleteDisappearingMessages::start(ctx.clone());

    RunningTasks {
        remove_unused_session_data,
        delete_disappearing_messages
    }
}
