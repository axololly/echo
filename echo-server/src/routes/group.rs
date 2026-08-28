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

    #[error("no group with that ID")]
    GroupNotFound
}

use GroupRouteError as G;

#[route("groups.get")]
#[ratelimit(10, 1m)]
pub async fn get_group(ctx: &mut EchoContext) -> RouteResult<Group> {
    let id: SnowflakeID = ctx
        .conn
        .receive()
        .await
        .context(E::InvalidData)?;

    let stmt = "SELECT name, avatar FROM groups WHERE id = $1";

    let (name, avatar): (String, AssetID) = fetch_opt_as!(&ctx.pool, stmt, id)
        .context(E::Database)?
        .context(E::Group(G::GroupNotFound))?;

    let stmt = "SELECT user_id, joined_at FROM groups WHERE group_id = $1";

    let members = fetch_all_as!(&ctx.pool, stmt, id).context(E::Database)?;

    Ok(Group {
        id,
        name,
        avatar,
        members
    })
}

#[derive(Deserialize, Serialize)]
pub struct CreateNewGroupData {
    pub name: String,
    pub initial_members: Vec<SnowflakeID>
}

#[route("groups.create")]
#[ratelimit(3, 2m)]
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
        let stmt = "
            SELECT 1 FROM friendships
            WHERE user1 = $1 AND user2 = $2
            OR user1 = $2 AND user2 = $1
        ";

        let friendship_exists: Option<i8> = fetch_opt_scalar!(&ctx.pool, stmt, &owner, other_user)
            .context(E::Database)?;

        if friendship_exists.is_none() {
            bail!(E::Group(G::FailedFriendConstaint));
        }
    }

    let group_id = SNOWFLAKE_GEN.next();

    execute!(
        &ctx.pool,
        "INSERT INTO groups (id, name, avatar) VALUES ($1, $2, $3)",
        group_id,
        &name,
        &*DEFAULT_PFP_ASSET_ID
    ).context(E::Database)?;

    let owner_join_time = Utc::now();
    let other_join_time = owner_join_time + TimeDelta::seconds(1);

    execute!(
        &ctx.pool,
        "INSERT INTO group_members (group_id, user_id, joined_at) VALUES ($1, $2, $3)",
        group_id,
        owner,
        owner_join_time
    ).context(E::Database)?;

    for other_user in &initial_members {
        execute!(
            &ctx.pool,
            "INSERT INTO group_members (group_id, user_id, joined_at) VALUES ($1, $2, $3)",
            group_id,
            other_user,
            other_join_time
        ).context(E::Database)?;
    }

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

    let group = Group {
        id: group_id,
        name,
        avatar: (*DEFAULT_PFP_ASSET_ID).clone(),
        members
    };

    Ok(group)
}
