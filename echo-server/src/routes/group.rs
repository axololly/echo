use chrono::{TimeDelta, Utc};
use rootcause::{bail, option_ext::OptionExt, prelude::ResultExt};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{error::{RouteError as E, RouteResult}, execute, fetch_all_as, fetch_opt_as, fetch_opt_scalar, route};
use echo_types::{AssetID, DEFAULT_PFP_ASSET_ID, Group, GroupMember, SNOWFLAKE_GEN, SnowflakeID};

use crate::router::EchoContext;

#[derive(Clone, Copy, Debug, Deserialize, Error, Serialize)]
pub enum GroupRouteError {
    #[error("cannot create group chat with a non-friend")]
    FailedFriendConstaint,

    #[error("no group found")]
    GroupNotFound
}

use GroupRouteError as G;

async fn get_group_from_db(
    ctx: &mut EchoContext,
    id: SnowflakeID
) -> RouteResult<Group>
{
    let stmt = "SELECT name, avatar, invite_code FROM groups WHERE id = $1";

    let data: (String, AssetID, String) = fetch_opt_as!(&ctx.pool, stmt, id)
        .context(E::Group(G::GroupNotFound))?;

    let (name, avatar, invite_code) = data;

    let stmt = "SELECT user_id, joined_at FROM groups WHERE group_id = $1";

    let members = fetch_all_as!(&ctx.pool, stmt, id);

    Ok(Group {
        id,
        name,
        avatar,
        members,
        invite_code
    })
}

#[route("groups.get")]
pub async fn get_group(ctx: &mut EchoContext) -> RouteResult<Group> {
    let id: SnowflakeID = ctx
        .conn
        .receive()
        .await
        .context(E::InvalidData)?;

    get_group_from_db(ctx, id).await
}

fn generate_random_invite_code() -> String {
    let mut result = String::new();
    let valid = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    for _ in 0 .. 8 {
        let i = (rand::random::<u64>() as usize) % valid.len();

        result.push_str(&valid[i .. i + 1]);
    }

    result
}

#[derive(Deserialize, Serialize)]
pub struct CreateNewGroupData {
    pub name: String,
    pub initial_members: Vec<SnowflakeID>
}

#[route("groups.create")]
pub async fn create_new_group(ctx: &mut EchoContext) -> RouteResult<Group> {
    let CreateNewGroupData {
        name,
        initial_members
    } = ctx
        .conn
        .receive()
        .await
        .context(E::InvalidData)?;

    let owner = ctx.user.unwrap();

    for other_user in &initial_members {
        let stmt1 = "
            SELECT 1 FROM friendships
            WHERE user1 = $1 AND user2 = $2
        ";

        let mut friendship_exists: Option<i8> = fetch_opt_scalar!(&ctx.pool, stmt1, &owner, other_user)
            .context(E::Database)?;

        if friendship_exists.is_none() {
            let stmt2 = "
                SELECT 1 FROM friendships
                WHERE user1 = $1 AND user2 = $2
            ";

            friendship_exists = fetch_opt_scalar!(&ctx.pool, stmt2, other_user, &owner)
                .context(E::Database)?;
        }

        if friendship_exists.is_none() {
            bail!(E::Group(G::FailedFriendConstaint));
        }
    }

    let group_id = SNOWFLAKE_GEN.next();

    let mut tx = ctx
        .pool
        .begin()
        .await
        .context(E::Database)?;

    execute!(
        &mut *tx,
        "INSERT INTO groups (id, name, avatar) VALUES ($1, $2, $3)",
        group_id,
        &name,
        &*DEFAULT_PFP_ASSET_ID
    );

    let owner_join_time = Utc::now();
    let other_join_time = owner_join_time + TimeDelta::seconds(1);

    execute!(
        &mut *tx,
        "INSERT INTO group_members (group_id, user_id, joined_at) VALUES ($1, $2, $3)",
        group_id,
        owner,
        owner_join_time
    );

    for other_user in &initial_members {
        execute!(
            &mut *tx,
            "INSERT INTO group_members (group_id, user_id, joined_at) VALUES ($1, $2, $3)",
            group_id,
            other_user,
            other_join_time
        );
    }

    tx.commit().await.context(E::Database)?;

    let mut members = vec![GroupMember {
        user_id: owner,
        joined_at: owner_join_time
    }];

    members.extend(
        initial_members
            .into_iter()
            .map(|user_id| GroupMember {
                user_id,
                joined_at: other_join_time
            })
    );

    let invite_code = loop {
        let code = generate_random_invite_code();

        let exists: Option<i8> = fetch_opt_scalar!(
            &ctx.pool,
            "SELECT 1 FROM groups WHERE invite_code = ?",
            &code
        ).context(E::Database)?;

        if exists.is_none() {
            break code;
        }
    };

    let group = Group {
        id: group_id,
        name,
        avatar: (*DEFAULT_PFP_ASSET_ID).clone(),
        members,
        invite_code
    };

    Ok(group)
}

#[route("groups.join")]
pub async fn join_new_group(ctx: &mut EchoContext) -> RouteResult<Group> {
    let invite_code: String = ctx
        .conn
        .receive()
        .await
        .context(E::InvalidData)?;

    let group_id: Option<SnowflakeID> = fetch_opt_scalar!(
        &ctx.pool,
        "SELECT id FROM groups WHERE invite_code = $1",
        &invite_code
    ).context(E::Database)?;

    let Some(id) = group_id else {
        bail!(E::Group(G::GroupNotFound));
    };

    let user = ctx.user.unwrap();
    let now = Utc::now();

    execute!(
        &ctx.pool,
        "INSERT INTO group_members (group_id, user_id, joined_at) VALUES ($1, $2, $3)",
        group_id,
        user,
        now
    );

    get_group_from_db(ctx, id).await
}

#[route("groups.leave")]
pub async fn leave_group(ctx: &mut EchoContext) -> RouteResult<()> {
    let user = ctx.user.unwrap();

    let group_id: SnowflakeID = ctx
        .conn
        .receive()
        .await
        .context(E::InvalidData)?;

    let stmt = "
        DELETE FROM group_members
        WHERE group_id = $1
        AND user_id = $2
        RETURNING 1
    ";

    let was_removed: Option<i8> = fetch_opt_scalar!(&ctx.pool, stmt, group_id, user)
        .context(E::Database)?;

    if was_removed.is_none() {
        bail!(E::Group(G::GroupNotFound));
    }

    Ok(())
}
