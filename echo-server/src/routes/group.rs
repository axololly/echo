use std::sync::LazyLock;

use chrono::{DateTime, TimeDelta, Utc};
use echo_types::{AssetID, BannedMember, Compressable, Compressed, Emoji, Group, GroupInvite, GroupMember, SNOWFLAKE_GEN, SnowflakeID, SqlxReadWatermark};
use file_type::FileType;
use regex::Regex;
use rootcause::{bail, option_ext::OptionExt, prelude::ResultExt};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::info;

use crate::{error::{RouteError as E, RouteResult}, events::{Event, dispatch_event_for_conversation}, execute, exists, fetch_all_as, fetch_all_scalar, fetch_one_as, fetch_one_scalar, fetch_opt_as, fetch_opt_scalar, ok, route, router::EchoContext};

/// An error related to groups.
#[derive(Clone, Debug, Deserialize, Error, Serialize)]
pub enum GroupRouteError {
    #[error("member {_0} is not a friend of the group owner")]
    InitialMemberNotFriend(SnowflakeID),

    #[error("only the owner can access this route")]
    OnlyForOwner,

    #[error("group could not be found")]
    GroupNotFound,

    #[error("member could not be found")]
    MemberNotFound,

    #[error("action is forbidden")]
    ActionForbidden,

    #[error("member is banned from this group")]
    MemberIsBanned {
        when: DateTime<Utc>,
        reason: Option<String>
    },

    #[error("group is full")]
    GroupIsFull,

    #[error("no megolm session for this epoch")]
    NoMegolmSession,

    #[error("emoji not found")]
    EmojiNotFound,

    #[error("cannot add more emojis to this group")]
    TooManyEmojis,

    #[error("unsupported MIME type for emoji: {_0}")]
    UnsupportedEmojiMimeType(String),

    #[error("not friends with person trying to add to group")]
    NotFriends
}

use GroupRouteError as G;

pub static VALID_GROUP_NAME_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^[^\p{Cc}]{1,30}$"#)
        .expect("failed to compile group chat name regex")
});

/// Generates a valid unique invite code by checking with the database
/// to ensure the code is unique.
///
/// This should typically only check with the server once, but in
/// extremely rare circumstances, it may query twice.
async fn generate_valid_invite_code(ctx: &mut EchoContext) -> RouteResult<GroupInvite> {
    let mut invite = GroupInvite::random();

    loop {
        let is_invalid = exists!(
            &ctx.pool,
            "SELECT 1 FROM groups WHERE invite_code = $1",
            invite
        );

        if !is_invalid {
            break;
        }

        invite = GroupInvite::random();
    }

    Ok(invite)
}

/// Get all the IDs of users in a specific group chat.
async fn get_group_members(
    ctx: &mut EchoContext,
    group_id: SnowflakeID
) -> RouteResult<Vec<SnowflakeID>> {
    let stmt = "
        SELECT user_id FROM conversation_members
        WHERE conversation_id = $1
        AND EXISTS (
            SELECT 1 FROM groups
            WHERE id = $1
        )
    ";

    let member_ids = fetch_all_scalar!(
        &ctx.pool,
        stmt,
        group_id
    );

    Ok(member_ids)
}

/// Data necessary for creating a new group.
///
/// The `initial_members` field **must** be less than 100
/// because that is the maximum group chat size.
#[derive(Deserialize, Serialize)]
pub struct CreateNewGroupData {
    pub name: Option<String>,
    pub initial_members: Vec<SnowflakeID>
}

#[route("groups.create")]
pub async fn create_new_group(ctx: &mut EchoContext) -> RouteResult<Group> {
    let CreateNewGroupData {
        name,
        initial_members
    } = ctx.stream.receive().await?;

    let owner = ctx.user.unwrap();

    if let Some(s) = &name && !VALID_GROUP_NAME_REGEX.is_match(s) {
        bail!(E::InvalidData);
    }

    if initial_members.len() >= 100 {
        bail!(E::InvalidData);
    }

    let stmt = "
        SELECT c.candidate_id
        FROM unnest($2::int8[]) AS c(candidate_id)
        WHERE NOT EXISTS (
            SELECT 1 FROM friendships f
            WHERE f.user1 = LEAST($1, c.candidate_id)
            AND f.user2 = GREATEST($1, c.candidate_id)
        )
        LIMIT 1
    ";

    let not_friends_with: Option<SnowflakeID> = fetch_opt_scalar!(
        &ctx.pool,
        stmt,
        owner,
        &initial_members
    );

    if let Some(id) = not_friends_with {
        bail!(E::Group(G::InitialMemberNotFriend(id)));
    }

    let group_name = name
        .as_deref()
        .unwrap_or("Unnamed group chat");

    let mut tx = ctx
        .pool
        .begin()
        .await
        .context(E::Database)?;

    let group_id = SNOWFLAKE_GEN.next();

    let invite_code = generate_valid_invite_code(ctx).await?;

    execute!(
        &mut *tx,
        "INSERT INTO conversations (id) VALUES ($1)",
        group_id
    );

    execute!(
        &mut *tx,
        "INSERT INTO groups (id, name, avatar, invite_code) VALUES ($1, $2, $3, $4)",
        group_id,
        &group_name,
        None::<i8>,
        invite_code
    );

    let now = Utc::now();

    execute!(
        &mut *tx,
        "INSERT INTO conversation_members (conversation_id, user_id, joined_at) VALUES ($1, $2, $3)",
        group_id,
        owner,
        now
    );

    let mut members = Vec::with_capacity(initial_members.len() + 1);

    members.push(GroupMember {
        user_id: owner,
        joined_at: now,
        read_watermark: None
    });

    for (i, &member_id) in initial_members.iter().enumerate() {
        let joined_at = now + TimeDelta::milliseconds(i as i64);

        execute!(
            &mut *tx,
            "INSERT INTO conversation_members (conversation_id, user_id, joined_at) VALUES ($1, $2, $3)",
            group_id,
            member_id,
            joined_at
        );

        members.push(GroupMember {
            user_id: member_id,
            joined_at,
            read_watermark: None
        });
    }

    tx.commit().await.context(E::Database)?;

    ctx.dispatcher.dispatch_contextual(
        members.iter().map(|m| m.user_id),
        |member_id| Event::MemberJoinedGroup { group_id, member_id }
    );

    info!("Created a group (ID: {group_id}, name: {name:?}, members: {initial_members:?})");

    Ok(Group {
        id: group_id,
        name: group_name.to_string(),
        members,
        avatar: None,
        created_at: now,
        invite_code,
        locked: false
    })
}

#[route("groups.get")]
pub async fn get_group(ctx: &mut EchoContext) -> RouteResult<Group> {
    let group_id: SnowflakeID = ctx.stream.receive().await?;

    if !is_group_member(ctx, group_id).await? {
        bail!(E::Group(G::GroupNotFound));
    }

    let stmt = "
        SELECT
            user_id,
            joined_at,
            last_message_id_read,
            last_message_read_at
        FROM conversation_members
        WHERE conversation_id = $1
    ";

    let raw_members = fetch_all_as!(
        &ctx.pool,
        stmt,
        group_id
    );

    let members = raw_members
        .into_iter()
        .map(|(user_id, joined_at, last_id, read_at)| GroupMember {
            user_id,
            joined_at,
            read_watermark: SqlxReadWatermark {
                last_message_id_read: last_id,
                last_message_read_at: read_at
            }.convert()
        })
        .collect();

    let stmt = "
        SELECT
            g.name,
            g.avatar,
            c.created_at,
            g.invite_code,
            g.locked
        FROM groups g
        INNER JOIN conversations c
            ON c.id = g.id
        WHERE g.id = $1
    ";

    let (name, avatar, created_at, invite_code, locked) = fetch_one_as!(
        &ctx.pool,
        stmt,
        group_id
    );

    Ok(Group {
        id: group_id,
        name,
        members,
        avatar,
        created_at,
        invite_code,
        locked
    })
}

/// Get the user ID of a group's owner.
///
/// Useful for checking if a user can do
/// actions limited to group owners.
async fn get_group_owner(
    ctx: &mut EchoContext,
    group_id: SnowflakeID
) -> RouteResult<SnowflakeID>
{
    let stmt = "
        SELECT user_id FROM conversation_members
        WHERE conversation_id = $1
        ORDER BY joined_at ASC
        LIMIT 1
    ";

    let owner: SnowflakeID = fetch_one_scalar!(
        &ctx.pool,
        stmt,
        group_id
    );

    Ok(owner)
}

/// An edit of the group's appearance.
///
/// This can only be done as the group owner.
///
/// If both `new_name` and `new_avatar` are set to
/// `None`, then this will return `InvalidData`.
#[derive(Deserialize, Serialize)]
pub struct GroupAppearanceUpdateData {
    pub group_id: SnowflakeID,
    pub new_name: Option<String>,
    pub new_avatar: Option<Vec<u8>>
}

#[route("groups.appearance.update")]
pub async fn update_group_appearance(ctx: &mut EchoContext) -> RouteResult<()> {
    let GroupAppearanceUpdateData {
        group_id,
        new_name,
        new_avatar
    } = ctx.stream.receive().await?;

    let user = ctx.user.unwrap();

    if get_group_owner(ctx, group_id).await? != user {
        bail!(E::Group(G::OnlyForOwner));
    }

    if let Some(name) = &new_name && !VALID_GROUP_NAME_REGEX.is_match(name) {
        bail!(E::InvalidData);
    }

    let new_avatar = if let Some(data) = new_avatar {
        let asset_id = ctx
            .asset_storage
            .upload(data)
            .await
            .context(E::Database)
            .attach("while uploading asset")?;

        Some(asset_id)
    }
    else {
        None
    };

    match (&new_name, new_avatar) {
        (Some(name), Some(avatar)) => execute!(
            &ctx.pool,
            "UPDATE groups SET name = $2, avatar = $3 WHERE id = $1",
            group_id,
            name,
            avatar
        ),
        (Some(name), None) => execute!(
            &ctx.pool,
            "UPDATE groups SET name = $2 WHERE id = $1",
            group_id,
            name
        ),
        (None, Some(avatar)) => execute!(
            &ctx.pool,
            "UPDATE groups SET avatar = $2 WHERE id = $1",
            group_id,
            avatar
        ),
        (None, None) => bail!(E::InvalidData)
    };

    info!("User {user} updated the group's appearance (new name: {new_name:?}, new avatar: {new_avatar:?})");

    dispatch_event_for_conversation(
        ctx,
        group_id,
        Event::GroupAppearanceUpdated {
            group_id,
            new_name,
            new_avatar
        }
    ).await?;

    Ok(())
}

/// Check if the user on this [`EchoContext`] is a
/// member of a given group.
async fn is_group_member(
    ctx: &mut EchoContext,
    group_id: SnowflakeID
) -> RouteResult<bool> {
    let user_id = ctx.user.unwrap();

    let stmt = "
        SELECT 1 FROM conversation_members
        WHERE conversation_id = $1
        AND user_id = $2
        AND EXISTS (
            SELECT 1 FROM groups WHERE id = $1
        )
    ";

    let is_member = exists!(
        &ctx.pool,
        stmt,
        group_id,
        user_id
    );

    Ok(is_member)
}

#[route("groups.join")]
pub async fn join_group(ctx: &mut EchoContext) -> RouteResult<Group> {
    let user_id = ctx.user.unwrap();

    let invite_code: GroupInvite = ctx.stream.receive().await?;

    let stmt = "
        SELECT id, name, avatar, created_at
        FROM groups
        WHERE invite_code = $1
        AND locked = FALSE
    ";

    let maybe_data: Option<(SnowflakeID, String, Option<AssetID>, DateTime<Utc>)> = fetch_opt_as!(
        &ctx.pool,
        stmt,
        invite_code
    );

    let Some((group_id, name, avatar, created_at)) = maybe_data else {
        bail!(E::Group(G::GroupNotFound));
    };

    if is_group_member(ctx, group_id).await? {
        bail!(E::Group(G::ActionForbidden));
    }

    let stmt = "
        SELECT banned_at, reason
        FROM group_banned_members
        WHERE group_id = $1
        AND member_id = $2
    ";

    let maybe_ban_data = fetch_opt_as!(
        &ctx.pool,
        stmt,
        group_id,
        user_id
    );

    if let Some((when, reason)) = maybe_ban_data {
        bail!(E::Group(G::MemberIsBanned { when, reason }));
    }

    let member_count: i64 = fetch_one_scalar!(
        &ctx.pool,
        "SELECT COUNT(user_id) FROM conversation_members WHERE conversation_id = $1",
        group_id
    );

    if member_count >= 100 {
        bail!(E::Group(G::GroupIsFull));
    }

    let mut tx = ctx
        .pool
        .begin()
        .await
        .context(E::Database)?;

    execute!(
        &mut *tx,
        "INSERT INTO conversation_members (conversation_id, user_id) VALUES ($1, $2)",
        group_id,
        user_id
    );

    execute!(
        &mut *tx,
        "UPDATE conversations SET epoch = epoch + 1 WHERE id = $1",
        group_id
    );

    tx.commit().await.context(E::Database)?;

    let stmt = "
        SELECT
            user_id,
            joined_at,
            last_message_id_read,
            last_message_read_at
        FROM conversation_members
        WHERE conversation_id = $1
    ";

    let members_data: Vec<(_, _, SqlxReadWatermark)> = fetch_all_as!(
        &ctx.pool,
        stmt,
        group_id
    );

    let members: Vec<_> = members_data
        .into_iter()
        .map(|(user_id, joined_at, raw)| GroupMember {
            user_id,
            joined_at,
            read_watermark: raw.convert()
        })
        .collect();

    info!("User joined group {name:?} (ID: {group_id}, members: {}) through invite code: {invite_code}", members.len());

    let group = Group {
        id: group_id,
        name,
        avatar,
        created_at,
        invite_code,
        members,
        locked: false
    };

    dispatch_event_for_conversation(ctx, group_id, Event::MemberJoinedGroup {
        group_id,
        member_id: user_id
    }).await?;

    Ok(group)
}

#[derive(Deserialize, Serialize)]
pub struct AddFriendToGroupData {
    pub group_id: SnowflakeID,
    pub friend_id: SnowflakeID
}

#[route("groups.add")]
pub async fn add_friend_to_group(ctx: &mut EchoContext) -> RouteResult<()> {
    let user_id = ctx.user.unwrap();

    let AddFriendToGroupData {
        group_id,
        friend_id
    } = ctx.stream.receive().await?;

    if user_id == friend_id {
        bail!(E::InvalidData);
    }

    let stmt = "
        SELECT 1 FROM friendships WHERE user1 = $1 AND user2 = $2
        UNION ALL
        SELECT 1 FROM friendships WHERE user1 = $2 AND user2 = $1
    ";

    let friends = exists!(
        &ctx.pool,
        stmt,
        user_id,
        friend_id
    );

    if !friends {
        bail!(E::Group(G::NotFriends))
    }

    if !is_group_member(ctx, group_id).await? {
        bail!(E::Group(G::GroupNotFound));
    }

    let stmt = "
        SELECT 1 FROM conversation_members
        WHERE conversation_id = $1
        AND user_id = $2
        AND EXISTS (
            SELECT 1 FROM groups WHERE id = $1
        )
    ";

    let is_already_member = exists!(
        &ctx.pool,
        stmt,
        group_id,
        friend_id
    );

    if is_already_member {
        return Ok(());
    }

    let stmt = "
        SELECT banned_at, reason
        FROM group_banned_members
        WHERE group_id = $1
        AND member_id = $2
    ";

    let maybe_ban_data = fetch_opt_as!(
        &ctx.pool,
        stmt,
        group_id,
        friend_id
    );

    if let Some((when, reason)) = maybe_ban_data {
        bail!(E::Group(G::MemberIsBanned { when, reason }));
    }

    let member_count: i64 = fetch_one_scalar!(
        &ctx.pool,
        "SELECT COUNT(user_id) FROM conversation_members WHERE conversation_id = $1",
        group_id
    );

    if member_count >= 100 {
        bail!(E::Group(G::GroupIsFull));
    }

    let mut tx = ctx
        .pool
        .begin()
        .await
        .context(E::Database)?;

    execute!(
        &mut *tx,
        "INSERT INTO conversation_members (conversation_id, user_id) VALUES ($1, $2)",
        group_id,
        friend_id
    );

    execute!(
        &mut *tx,
        "UPDATE conversations SET epoch = epoch + 1 WHERE id = $1",
        group_id
    );

    tx.commit().await.context(E::Database)?;

    info!("User added friend {friend_id} to group {group_id}");

    dispatch_event_for_conversation(ctx, group_id, Event::MemberJoinedGroup {
        group_id,
        member_id: friend_id
    }).await?;

    Ok(())
}

#[route("groups.leave")]
pub async fn leave_group(ctx: &mut EchoContext) -> RouteResult<()> {
    let user_id = ctx.user.unwrap();

    let group_id: SnowflakeID = ctx.stream.receive().await?;

    if !is_group_member(ctx, group_id).await? {
        bail!(E::Group(G::GroupNotFound));
    }

    let mut tx = ctx
        .pool
        .begin()
        .await
        .context(E::Database)?;

    let stmt = "
        DELETE FROM conversation_members
        WHERE conversation_id = $1
        AND user_id = $2
    ";

    execute!(
        &mut *tx,
        stmt,
        group_id,
        user_id
    );

    let members = get_group_members(ctx, group_id).await?;

    info!("User left group {group_id}");

    if members.is_empty() {
        info!("Group has no more members, deleting...");

        execute!(
            &mut *tx,
            "DELETE FROM conversations WHERE id = $1",
            group_id
        );
    }
    else {
        info!("Group now has {} members left", members.len());

        ctx.dispatcher.dispatch(
            members,
            Event::MemberLeftGroup {
                group_id,
                member_id: user_id
            }
        );
    }

    execute!(
        &mut *tx,
        "UPDATE conversations SET epoch = epoch + 1 WHERE id = $1",
        group_id
    );

    tx.commit().await.context(E::Database)?;

    Ok(())
}

/// Data necessarily to remove a member.
///
/// This is used for both kicking a member
/// and banning a member.
#[derive(Deserialize, Serialize)]
pub struct KickMemberData {
    pub group_id: SnowflakeID,
    pub member_id: SnowflakeID
}

#[route("groups.members.kick")]
pub async fn kick_group_member(ctx: &mut EchoContext) -> RouteResult<()> {
    let user = ctx.user.unwrap();

    let KickMemberData {
        group_id,
        member_id
    } = ctx.stream.receive().await?;

    let owner = get_group_owner(ctx, group_id).await?;

    if owner != user {
        bail!(E::Group(G::OnlyForOwner));
    }

    if member_id == owner {
        bail!(E::Group(G::ActionForbidden));
    }

    let mut tx = ctx
        .pool
        .begin()
        .await
        .context(E::Database)?;

    let stmt = "
        DELETE FROM conversation_members
        WHERE conversation_id = $1
        AND user_id = $2
    ";

    execute!(
        &mut *tx,
        stmt,
        group_id,
        member_id
    );

    execute!(
        &mut *tx,
        "UPDATE conversations SET epoch = epoch + 1 WHERE id = $1",
        group_id
    );

    dispatch_event_for_conversation(ctx, group_id, Event::MemberLeftGroup {
        group_id,
        member_id
    }).await?;

    info!("User kicked member {member_id} out of group {group_id}");

    Ok(())
}

/// Data necessarily to ban a member.
///
/// The owner can optionally specify a reason
/// for banning a user.
#[derive(Deserialize, Serialize)]
pub struct BanMemberData {
    pub group_id: SnowflakeID,
    pub member_id: SnowflakeID,
    pub reason: Option<String>
}

#[route("groups.members.ban")]
pub async fn ban_group_member(ctx: &mut EchoContext) -> RouteResult<()> {
    let user = ctx.user.unwrap();

    let BanMemberData {
        group_id,
        member_id,
        reason
    } = ctx.stream.receive().await?;

    let owner = get_group_owner(ctx, group_id).await?;

    if owner != user {
        bail!(E::Group(G::OnlyForOwner));
    }

    if member_id == owner {
        bail!(E::Group(G::ActionForbidden));
    }

    let mut tx = ctx
        .pool
        .begin()
        .await
        .context(E::Database)?;

    let stmt = "
        DELETE FROM conversation_members
        WHERE conversation_id = $1
        AND user_id = $2
    ";

    execute!(
        &mut *tx,
        stmt,
        group_id,
        member_id
    );

    let stmt = "
        INSERT INTO group_banned_members (
            group_id,
            member_id,
            reason
        ) VALUES ($1, $2, $3)
    ";

    execute!(
        &mut *tx,
        stmt,
        group_id,
        member_id,
        &reason
    );

    execute!(
        &mut *tx,
        "UPDATE groups SET epoch = epoch + 1 WHERE id = $1",
        group_id
    );

    tx.commit().await.context(E::Database)?;

    info!("User banned member {member_id} from group {group_id} for reason: {reason:?}");

    dispatch_event_for_conversation(ctx, group_id, Event::MemberLeftGroup {
        group_id,
        member_id
    }).await?;

    Ok(())
}

/// Data necessarily to remove a member.
///
/// This is used for both kicking a member
/// and banning a member.
#[derive(Deserialize, Serialize)]
pub struct UnbanMemberData {
    pub group_id: SnowflakeID,
    pub member_id: SnowflakeID
}

#[route("groups.members.unban")]
pub async fn unban_group_member(ctx: &mut EchoContext) -> RouteResult<()> {
    let user = ctx.user.unwrap();

    let UnbanMemberData {
        group_id,
        member_id
    } = ctx.stream.receive().await?;

    if get_group_owner(ctx, group_id).await? != user {
        bail!(E::Group(G::OnlyForOwner));
    }

    let stmt = "
        DELETE FROM group_banned_members
        WHERE group_id = $1
        AND member_id = $2
        RETURNING 1
    ";

    let member_is_banned = exists!(
        &ctx.pool,
        stmt,
        group_id,
        member_id
    );

    if !member_is_banned {
        bail!(E::Group(G::MemberNotFound));
    }

    info!("User unbanned previous member {member_id} from group {group_id}");

    Ok(())
}

#[route("groups.members.banned.get")]
pub async fn get_banned_members_list(ctx: &mut EchoContext) -> RouteResult<Vec<BannedMember>> {
    let user = ctx.user.unwrap();

    let group_id: SnowflakeID = ctx.stream.receive().await?;

    if get_group_owner(ctx, group_id).await? != user {
        bail!(E::Group(G::OnlyForOwner));
    }

    let stmt = "
        SELECT member_id, banned_at, reason
        FROM group_banned_members
        WHERE group_id = $1
    ";

    let members: Vec<BannedMember> = fetch_all_as!(
        &ctx.pool,
        stmt,
        group_id
    );

    Ok(members)
}

#[route("groups.invites.rotate")]
pub async fn rotate_group_invite_code(ctx: &mut EchoContext) -> RouteResult<GroupInvite> {
    let user_id = ctx.user.unwrap();

    let group_id: SnowflakeID = ctx.stream.receive().await?;

    let group_owner = get_group_owner(ctx, group_id).await?;

    if group_owner != user_id {
        bail!(E::Group(G::OnlyForOwner));
    }

    let new_invite = generate_valid_invite_code(ctx).await?;

    execute!(
        &ctx.pool,
        "UPDATE groups SET invite_code = $2 WHERE id = $1",
        group_id,
        new_invite
    );

    info!("User updated invite code to {new_invite} for group {group_id}");

    dispatch_event_for_conversation(
        ctx,
        group_id,
        Event::GroupInviteRotated {
            group_id,
            new_invite
        }
    ).await?;

    Ok(new_invite)
}

/// Data for updating the group's lock.
#[derive(Deserialize, Serialize)]
pub struct UpdateGroupLockData {
    pub group_id: SnowflakeID,
    pub new_lock_status: bool
}

#[route("groups.lock.update")]
pub async fn change_group_lock(ctx: &mut EchoContext) -> RouteResult<()> {
    let UpdateGroupLockData {
        group_id,
        new_lock_status
    } = ctx.stream.receive().await?;

    if get_group_owner(ctx, group_id).await? != ctx.user.unwrap() {
        bail!(E::Group(G::OnlyForOwner));
    }

    let old_lock_status: Option<bool> = fetch_opt_scalar!(
       &ctx.pool,
        "UPDATE groups SET locked = $2 WHERE id = $1 RETURNING OLD.locked",
        group_id
    );

    let Some(status) = old_lock_status else {
        bail!(E::Group(G::GroupNotFound));
    };

    if new_lock_status != status {
        dispatch_event_for_conversation(ctx, group_id, Event::GroupLockStatusUpdated {
            group_id,
            locked: new_lock_status
        }).await?;

        let verb = if new_lock_status { "locked" } else { "unlocked" };

        info!("User {verb} group {group_id}");
    }

    Ok(())
}

#[route("groups.emojis.get")]
pub async fn get_group_emoji(ctx: &mut EchoContext) -> RouteResult<Emoji> {
    let emoji_id: SnowflakeID = ctx.stream.receive().await?;

    fetch_opt_as!(
        &ctx.pool,
        "SELECT * FROM group_emojis WHERE id = $1",
        emoji_id
    ).context(E::Group(G::EmojiNotFound))
}

#[route("groups.emojis.all.get")]
pub async fn get_all_group_emoji_ids(ctx: &mut EchoContext) -> RouteResult<Compressed<Vec<Emoji>>> {
    let group_id: SnowflakeID = ctx.stream.receive().await?;

    if !is_group_member(ctx, group_id).await? {
        bail!(E::Group(G::GroupNotFound));
    }

    let emojis: Vec<Emoji> = fetch_all_as!(
        &ctx.pool,
        "SELECT * FROM group_emojis WHERE group_id = $1",
        group_id
    );

    Ok(emojis.compress())
}

/// Data for uploading a new emoji.
///
/// The content is uploaded separately,
/// unencrypted and will be converted to
/// WebP for efficiency.
#[derive(Deserialize, Serialize)]
pub struct CreateNewEmojiData {
    pub group_id: SnowflakeID,
    pub name: String
}

const VALID_EMOJI_MIME_TYPES: &[&str] = &[
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp"
];

static VALID_EMOJI_NAME_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-zA-Z0-9_\-.]{1,30}$").expect("failed to compile regex")
});

#[route("groups.emojis.create")]
pub async fn create_new_group_emoji(ctx: &mut EchoContext) -> RouteResult<Emoji> {
    let CreateNewEmojiData {
        group_id,
        name
    } = ctx.stream.receive().await?;

    if !VALID_EMOJI_NAME_REGEX.is_match(&name) {
        bail!(E::InvalidData);
    }

    if get_group_owner(ctx, group_id).await? != ctx.user.unwrap() {
        bail!(E::Group(G::OnlyForOwner));
    }

    let count: i64 = fetch_one_scalar!(
        &ctx.pool,
        "SELECT COUNT(*) FROM group_emojis WHERE group_id = $1",
        group_id
    );

    // My Design said that I would have 250 static and 250 animated,
    // but just having a lump sum is easier to implement, so I'll
    // say it's for added flexibility and easier implementation.
    if count >= 500 {
        bail!(E::Group(G::TooManyEmojis));
    }

    ctx.stream.send(ok!(())).await?;

    // 250KB limit
    let asset: Vec<u8> = ctx.stream.receive_capped(250_000).await?;

    let mime_type = FileType::from_bytes(&asset).media_types()[0];

    if !VALID_EMOJI_MIME_TYPES.contains(&mime_type) {
        bail!(E::Group(G::UnsupportedEmojiMimeType(mime_type.to_string())));
    }

    let emoji_id = SNOWFLAKE_GEN.next();

    let mut tx = ctx
        .pool
        .begin()
        .await
        .context(E::Database)?;

    let asset_id = AssetID::from_bytes(&asset);

    execute!(
        &mut *tx,
        "INSERT INTO group_emojis (id, group_id, name, asset_id) VALUES ($1, $2, $3, $4)",
        emoji_id,
        group_id,
        &name,
        asset_id
    );

    ctx
        .asset_storage
        .upload(asset)
        .await
        .context(E::Database)
        .attach("while uploading emoji asset to asset storage")?;

    tx.commit().await.context(E::Database)?;

    let emoji = Emoji {
        id: emoji_id,
        group_id,
        name,
        asset_id
    };

    dispatch_event_for_conversation(
        ctx,
        group_id,
        Event::NewGroupEmoji(emoji.clone())
    ).await?;

    info!("User uploaded new emoji to group {group_id}: {emoji:?}");

    Ok(emoji)
}

/// Data related to deleting an emoji.
///
/// The group ID is specified to make checking ownership easier.
#[derive(Deserialize, Serialize)]
pub struct DeleteGroupEmojiData {
    pub group_id: SnowflakeID,
    pub emoji_id: SnowflakeID
}

#[route("groups.emojis.delete")]
pub async fn delete_group_emoji(ctx: &mut EchoContext) -> RouteResult<()> {
    let DeleteGroupEmojiData {
        group_id,
        emoji_id
    } = ctx.stream.receive().await?;

    if get_group_owner(ctx, group_id).await? != ctx.user.unwrap() {
        bail!(E::Group(G::OnlyForOwner));
    }

    let mut tx = ctx
        .pool
        .begin()
        .await
        .context(E::Database)?;

    let maybe_asset_id: Option<AssetID> = fetch_opt_scalar!(
        &mut *tx,
        "DELETE FROM group_emojis WHERE id = $1 RETURNING asset_id",
        emoji_id
    );

    let Some(asset_id) = maybe_asset_id else {
        bail!(E::Group(G::EmojiNotFound));
    };

    ctx
        .asset_storage
        .delete(asset_id)
        .await
        .context(E::Database)
        .attach("while deleting emoji blob from asset storage")?;

    tx.commit().await.context(E::Database)?;

    dispatch_event_for_conversation(
        ctx,
        group_id,
        Event::GroupEmojiDeleted(emoji_id)
    ).await?;

    info!("User deleted emoji {emoji_id} in group {group_id}");

    Ok(())
}
