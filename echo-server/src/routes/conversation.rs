use chrono::TimeDelta;
use echo_types::SnowflakeID;
use rootcause::{bail, prelude::ResultExt};
use serde::{Deserialize, Serialize};
use sqlx::postgres::types::PgInterval;
use thiserror::Error;

use crate::{error::{RouteError as E, RouteResult}, events::{Event, dispatch_event_for_conversation}, execute, exists, fetch_opt_scalar, route, router::EchoContext};

#[derive(Clone, Debug, Deserialize, Error, Serialize)]
pub enum ConversationRouteError {
    #[error("conversation not found")]
    ConversationNotFound
}

use ConversationRouteError as C;

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

#[route("conversations.timers.default.get")]
pub async fn get_default_message_timer(ctx: &mut EchoContext) -> RouteResult<Option<TimeDelta>> {
    let conversation_id = ctx.stream.receive().await?;

    if !is_part_of_conversation(ctx, conversation_id).await? {
        bail!(E::Conversation(C::ConversationNotFound));
    }

    let maybe_interval: Option<PgInterval> = fetch_opt_scalar!(
        &ctx.pool,
        "SELECT message_timer FROM conversations WHERE id = $1",
        conversation_id,
        ctx.user.unwrap()
    );

    let maybe_timer = maybe_interval.map(|iv| {
        TimeDelta::days(iv.months as i64 * 30)
        + TimeDelta::days(iv.days as i64)
        + TimeDelta::microseconds(iv.microseconds)
    });

    Ok(maybe_timer)
}

#[derive(Deserialize, Serialize)]
pub struct UpdateDefaultMessageTimerData {
    pub conversation_id: SnowflakeID,
    pub new_message_timer: Option<TimeDelta>
}

#[route("conversations.timers.default.update")]
pub async fn update_default_message_timer(ctx: &mut EchoContext) -> RouteResult<()> {
    let UpdateDefaultMessageTimerData {
        conversation_id,
        new_message_timer
    } = ctx.stream.receive().await?;

    if !is_part_of_conversation(ctx, conversation_id).await? {
        bail!(E::Conversation(C::ConversationNotFound));
    }

    execute!(
        &ctx.pool,
        "UPDATE conversations SET message_timer = $2 WHERE id = $1",
        conversation_id,
        new_message_timer
    );

    dispatch_event_for_conversation(
        ctx,
        conversation_id,
        Event::ConversationTimerUpdated {
            conversation_id,
            new_message_timer
        }
    ).await?;

    Ok(())
}
