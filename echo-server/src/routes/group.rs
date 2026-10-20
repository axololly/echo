use std::collections::{HashMap, HashSet};

use chrono::{DateTime, TimeDelta, Utc};
use echo_types::{__convert_encrypted_to_crypto_box, AssetID, BannedMember, BoxPublicKey, CryptoBox, Encrypted, Group, GroupInvite, GroupMember, Message, MessageBody, SNOWFLAKE_GEN, Secret, SnowflakeID, SqlxMegolmMessage};
use rootcause::{bail, option_ext::OptionExt, prelude::ResultExt};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use vodozemac::{megolm::{GroupSessionPickle, MegolmMessage, SessionKey}};

use crate::{error::{RouteError as E, RouteResult}, events::Event, execute, exists, fetch_all_as, fetch_all_scalar, fetch_one_as, fetch_one_scalar, fetch_opt_as, fetch_opt_scalar, ok, route, router::EchoContext};

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

    #[error("no megolm session for this epoch")]
    NoMegolmSession
}

use GroupRouteError as G;

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
        SELECT user_id FROM group_members
        WHERE group_id = $1
    ";

    let member_ids = fetch_all_scalar!(
        &ctx.pool,
        stmt,
        group_id
    );

    Ok(member_ids)
}

/// Dispatch the same [`Event`] to all current
/// members of a group chat.
async fn dispatch_event_for_group(
    ctx: &mut EchoContext,
    group_id: SnowflakeID,
    event: Event
) -> RouteResult<()> {
    let members = get_group_members(ctx, group_id).await?;

    ctx.dispatcher.dispatch(members, event).await;

    Ok(())
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

    if initial_members.is_empty() || initial_members.len() > 99 {
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
        "INSERT INTO groups (id, name, avatar, invite_code) VALUES ($1, $2, $3, $4)",
        group_id,
        &group_name,
        None::<i8>,
        invite_code
    );

    let now = Utc::now();

    execute!(
        &mut *tx,
        "INSERT INTO group_members (group_id, user_id, joined_at) VALUES ($1, $2, $3)",
        group_id,
        owner,
        now
    );

    let mut members = Vec::with_capacity(initial_members.len() + 1);

    members.push(GroupMember {
        user_id: owner,
        joined_at: now
    });

    for (i, &member_id) in initial_members.iter().enumerate() {
        let joined_at = now + TimeDelta::milliseconds(i as i64);

        execute!(
            &mut *tx,
            "INSERT INTO group_members (group_id, user_id, joined_at) VALUES ($1, $2, $3)",
            group_id,
            member_id,
            joined_at
        );

        members.push(GroupMember {
            user_id: member_id,
            joined_at
        });
    }

    tx.commit().await.context(E::Database)?;

    ctx.dispatcher.dispatch_contextual(
        members.iter().map(|m| m.user_id),
        |member_id| Event::MemberJoinedGroup { group_id, member_id }
    ).await;

    Ok(Group {
        id: group_id,
        name: group_name.to_string(),
        members,
        avatar: None,
        created_at: now,
        invite_code
    })
}

#[route("groups.get")]
pub async fn get_group(ctx: &mut EchoContext) -> RouteResult<Group> {
    let group_id: SnowflakeID = ctx.stream.receive().await?;

    if !is_group_member(ctx, group_id).await? {
        bail!(E::Group(G::GroupNotFound));
    }

    let (name, avatar, created_at, invite_code) = fetch_one_as!(
        &ctx.pool,
        "SELECT name, avatar, created_at, invite_code FROM groups WHERE id = $1",
        group_id
    );

    let members = fetch_all_as!(
        &ctx.pool,
        "SELECT user_id, joined_at FROM group_members WHERE group_id = $1",
        group_id
    );

    Ok(Group {
        id: group_id,
        name,
        avatar,
        members,
        created_at,
        invite_code
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
        SELECT user_id FROM group_members
        WHERE group_id = $1
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
    pub new_avatar: Option<AssetID>
}

#[route("groups.appearance.edit")]
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

    dispatch_event_for_group(
        ctx,
        group_id,
        Event::GroupAppearanceUpdated {
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
        SELECT 1 FROM group_members
        WHERE group_id = $1
        AND user_id = $2
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

    let maybe_data: Option<(SnowflakeID, String, Option<AssetID>, DateTime<Utc>)> = fetch_opt_as!(
        &ctx.pool,
        "SELECT id, name, avatar, created_at FROM groups WHERE invite_code = $1",
        invite_code
    );

    let Some((group_id, name, avatar, created_at)) = maybe_data else {
        bail!(E::Group(G::GroupNotFound));
    };

    if is_group_member(ctx, group_id).await? {
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
        user_id
    );

    if let Some((when, reason)) = maybe_ban_data {
        bail!(E::Group(G::MemberIsBanned { when, reason }));
    }

    let mut tx = ctx
        .pool
        .begin()
        .await
        .context(E::Database)?;

    execute!(
        &mut *tx,
        "INSERT INTO group_members (group_id, user_id) VALUES ($1, $2)",
        group_id,
        user_id
    );

    execute!(
        &mut *tx,
        "UPDATE groups SET epoch = epoch + 1 WHERE id = $1",
        group_id
    );

    tx.commit().await.context(E::Database)?;

    let members_data: Vec<(SnowflakeID, DateTime<Utc>)> = fetch_all_as!(
        &ctx.pool,
        "SELECT user_id, joined_at FROM group_members WHERE group_id = $1",
        group_id
    );

    let members = members_data
        .into_iter()
        .map(|(user_id, joined_at)| GroupMember { user_id, joined_at })
        .collect();

    let group = Group {
        id: group_id,
        name,
        avatar,
        created_at,
        invite_code,
        members
    };

    dispatch_event_for_group(ctx, group_id, Event::MemberJoinedGroup {
        group_id,
        member_id: user_id
    }).await?;

    Ok(group)
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
        DELETE FROM group_members
        WHERE group_id = $1
        AND user_id = $2
    ";

    execute!(
        &mut *tx,
        stmt,
        group_id,
        user_id
    );

    let members = get_group_members(ctx, group_id).await?;

    if members.is_empty() {
        execute!(
            &mut *tx,
            "DELETE FROM groups WHERE id = $1",
            group_id
        );
    }
    else {
        ctx.dispatcher.dispatch(
            members,
            Event::MemberLeftGroup {
                group_id,
                member_id: user_id
            }
        ).await;
    }

    execute!(
        &mut *tx,
        "UPDATE groups SET epoch = epoch + 1 WHERE id = $1",
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
        DELETE FROM group_members
        WHERE group_id = $1
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
        "UPDATE groups SET epoch = epoch + 1 WHERE id = $1",
        group_id
    );

    dispatch_event_for_group(ctx, group_id, Event::MemberLeftGroup {
        group_id,
        member_id
    }).await?;

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
        DELETE FROM group_members
        WHERE group_id = $1
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
        reason
    );

    execute!(
        &mut *tx,
        "UPDATE groups SET epoch = epoch + 1 WHERE id = $1",
        group_id
    );

    tx.commit().await.context(E::Database)?;

    dispatch_event_for_group(ctx, group_id, Event::MemberLeftGroup {
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

    dispatch_event_for_group(
        ctx,
        group_id,
        Event::GroupInviteRotated {
            group_id,
            new_invite
        }
    ).await?;

    Ok(new_invite)
}

/// A single group chat member's session,
/// packaging their outbound session and
/// the inbound sessions of all other members.
#[derive(Deserialize, Serialize)]
pub struct GroupChatSession {
    pub outbound: Encrypted<GroupSessionPickle>,
    pub inbounds: HashMap<SnowflakeID, CryptoBox<SessionKey>>
}

#[route("groups.sessions.get")]
pub async fn get_latest_group_chat_session(ctx: &mut EchoContext) -> RouteResult<GroupChatSession> {
    let group_id: SnowflakeID = ctx.stream.receive().await?;

    if !is_group_member(ctx, group_id).await? {
        bail!(E::Group(G::GroupNotFound));
    }

    let user_id = ctx.user.unwrap();

    let stmt = "
        SELECT
            gsk.receiver,
            gsk.blob
        FROM group_session_keys gsk
        INNER JOIN groups g
            ON g.id = gsk.group_id
            AND g.epoch = gsk.epoch
        WHERE g.id = $1
        AND gsk.sender = $2
    ";

    let rows: Vec<(SnowflakeID, Encrypted<GroupSessionPickle>)> = fetch_all_as!(
        &ctx.pool,
        stmt,
        group_id,
        user_id
    );

    let mut outbound = None;

    let mut inbounds = HashMap::new();

    let mut members = get_group_members(ctx, group_id)
        .await?
        .into_iter()
        .collect::<HashSet<_>>();

    for (receiver, enc) in rows {
        if !members.remove(&receiver) {
            continue;
        }

        if receiver == user_id {
            outbound = Some(enc);
        }
        else {
            let key = __convert_encrypted_to_crypto_box(enc)
                .cast::<SessionKey>();

            inbounds.insert(receiver, key);
        }
    }

    let err = E::Group(G::NoMegolmSession);

    if !members.is_empty() {
        bail!(err);
    }

    let outbound = outbound.context(err)?;

    let session = GroupChatSession {
        outbound,
        inbounds
    };

    Ok(session)
}

#[route("groups.sessions.ensure")]
pub async fn ensure_latest_megolm_session(ctx: &mut EchoContext) -> RouteResult<()> {
    let group_id: SnowflakeID = ctx.stream.receive().await?;

    if !is_group_member(ctx, group_id).await? {
        bail!(E::Group(G::GroupNotFound));
    }

    let user_id = ctx.user.unwrap();

    let epoch: i64 = fetch_one_scalar!(
        &ctx.pool,
        "SELECT epoch FROM groups WHERE id = $1",
        group_id
    );

    let stmt = "
        SELECT receiver
        FROM group_session_keys
        WHERE group_id = $1
        AND sender = $2
        AND epoch = $3
    ";

    let other_members: Vec<SnowflakeID> = fetch_all_scalar!(
        &ctx.pool,
        stmt,
        group_id,
        user_id,
        epoch
    );

    if !other_members.is_empty() {
        ctx.stream.send(ok!(false)).await?;

        return Ok(());
    }

    ctx.stream.send(ok!(true)).await?;

    let stmt = "
        SELECT
            gm.user_id,
            upk.box_public_key
        FROM group_members gm
        INNER JOIN users_public_keys upk
            ON upk.user_id = gm.user_id
        WHERE gm.group_id = $1
        AND gm.user_id != $2
    ";

    let raw_other_members: Vec<(SnowflakeID, BoxPublicKey)> = fetch_all_as!(
        &ctx.pool,
        stmt,
        group_id,
        user_id
    );

    let mut other_members: HashMap<SnowflakeID, BoxPublicKey> = raw_other_members
        .into_iter()
        .collect();

    ctx.stream.send(ok!(other_members)).await?;

    let session: GroupChatSession = ctx.stream.receive().await?;

    other_members.retain(|id, _| !session.inbounds.contains_key(id));

    if !other_members.is_empty() {
        bail!(E::InvalidData);
    }

    let mut tx = ctx
        .pool
        .begin()
        .await
        .context(E::Database)?;

    let stmt = "
        INSERT INTO group_session_keys (
            group_id,
            epoch,
            sender,
            receiver,
            blob
        ) VALUES ($1, $2, $3, $4, $5)
    ";

    execute!(
        &mut *tx,
        stmt,
        group_id,
        epoch,
        user_id,
        user_id,
        session.outbound
    );

    for (member_id, session_key) in session.inbounds {
        execute!(
            &mut *tx,
            stmt,
            group_id,
            epoch,
            user_id,
            member_id,
            session_key
        );
    }

    tx.commit().await.context(E::Database)?;

    Ok(())
}

/// Data necessary for sending a message into a group.
///
/// This requires a Megolm session to have been uploaded to the
/// server prior to accessing this route.
#[derive(Deserialize, Serialize)]
pub struct SendGroupMessageData {
    pub group_id: SnowflakeID,
    pub replied_to: Option<SnowflakeID>,
    pub message_body: Encrypted<MessageBody>,
    pub key_for_author: Encrypted<Secret>,
    pub key_for_others: MegolmMessage
}

#[route("groups.messages.send")]
pub async fn send_group_message(ctx: &mut EchoContext) -> RouteResult<Message> {
    let author_id = ctx.user.unwrap();

    let SendGroupMessageData {
        group_id,
        replied_to,
        message_body,
        key_for_author,
        key_for_others
    } = ctx.stream.receive().await?;

    if !is_group_member(ctx, group_id).await? {
        bail!(E::Group(G::GroupNotFound));
    }

    let epoch: i64 = fetch_one_scalar!(
        &ctx.pool,
        "SELECT epoch FROM groups WHERE id = $1",
        group_id
    );

    let message_id = SNOWFLAKE_GEN.next();

    let members = get_group_members(ctx, group_id).await?;

    let mut tx = ctx
        .pool
        .begin()
        .await
        .context(E::Database)?;

    let stmt = "
        INSERT INTO group_messages (
            id,
            group_id,
            parent_id,
            author,
            blob
        ) VALUES ($1, $2, $3, $4, $5)
    ";

    execute!(
        &mut *tx,
        stmt,
        message_id,
        group_id,
        replied_to,
        author_id,
        &message_body
    );

    let stmt = "
        INSERT INTO message_decryption_keys (
            message_id,
            user_id,
            blob
        ) VALUES ($1, $2, $3)
    ";

    execute!(
        &mut *tx,
        stmt,
        message_id,
        author_id,
        key_for_author
    );

    let stmt = "
        INSERT INTO pending_group_message_keys (
            message_id,
            recipient,
            epoch,
            blob
        ) VALUES ($1, $2, $3, $4)
    ";

    let key_for_others = SqlxMegolmMessage::from(key_for_others);

    for member_id in members {
        if member_id == author_id {
            continue;
        }

        execute!(
            &mut *tx,
            stmt,
            message_id,
            member_id,
            epoch,
            &key_for_others
        );
    }

    tx.commit().await.context(E::Database)?;

    dispatch_event_for_group(
        ctx,
        group_id,
        Event::NewGroupMessage {
            group_id,
            message_id,
            author_id
        }
    ).await?;

    Ok(Message {
        id: message_id,
        replied_to,
        author: author_id,
        body: message_body
    })
}
