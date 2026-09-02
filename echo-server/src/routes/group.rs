use std::collections::HashMap;

use chrono::{TimeDelta, Utc};
use crypto_box::PublicKey;
use rootcause::{bail, option_ext::OptionExt, prelude::ResultExt};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use vodozemac::megolm::{GroupSessionPickle, MegolmMessage, SessionKey};

use crate::{error::{RouteError as E, RouteResult}, execute, fetch_all_as, fetch_all_scalar, fetch_one_scalar, fetch_opt_as, fetch_opt_scalar, ok, route};
use echo_types::{AssetID, CryptoBox, DEFAULT_PFP_ASSET_ID, Encrypted, Group, GroupMember, Message, MessageBody, MessageType, SNOWFLAKE_GEN, SnowflakeID};

use crate::router::EchoContext;

#[derive(Clone, Copy, Debug, Deserialize, Error, Serialize)]
pub enum GroupRouteError {
    #[error("cannot create group chat with a non-friend")]
    FailedFriendConstaint,

    #[error("no group found")]
    GroupNotFound,

    #[error("you are banned from that group")]
    BannedFromGroup,

    #[error("only accessible by the owner")]
    OnlyForOwner,

    #[error("this interaction is not applicable for the owner (kick/ban/unban)")] // TODO: this needs functionality
    NotForOwner,

    #[error("no megolm session for the current epoch was found")]
    NoMegolmSession
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

    let stmt = "SELECT user_id, joined_at FROM conversation_members WHERE conversation_id = $1";

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
        .stream
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
        .stream
        .receive()
        .await
        .context(E::InvalidData)?;

    let owner = ctx.user.unwrap();

    for &other_user in &initial_members {
        let stmt = "
            SELECT 1 FROM friendships
            WHERE user1 = $1 AND user2 = $2
        ";

        let friendship_exists: Option<i32> = fetch_opt_scalar!(
            &ctx.pool,
            stmt,
            owner.min(other_user),
            owner.max(other_user)
        );

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
        "INSERT INTO conversations (id, created_at) VALUES ($1, $2)",
        group_id,
        Utc::now()
    );

    let invite_code = loop {
        let code = generate_random_invite_code();

        let exists: Option<i32> = fetch_opt_scalar!(
            &ctx.pool,
            "SELECT 1 FROM groups WHERE invite_code = $1",
            &code
        );

        if exists.is_none() {
            break code;
        }
    };

    execute!(
        &mut *tx,
        "INSERT INTO groups (id, name, avatar, invite_code) VALUES ($1, $2, $3, $4)",
        group_id,
        &name,
        &*DEFAULT_PFP_ASSET_ID,
        &invite_code
    );

    let owner_join_time = Utc::now();
    let other_join_time = owner_join_time + TimeDelta::seconds(1);

    execute!(
        &mut *tx,
        "INSERT INTO conversation_members (conversation_id, user_id, joined_at) VALUES ($1, $2, $3)",
        group_id,
        owner,
        owner_join_time
    );

    for other_user in &initial_members {
        execute!(
            &mut *tx,
            "INSERT INTO conversation_members (conversation_id, user_id, joined_at) VALUES ($1, $2, $3)",
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

    let group = Group {
        id: group_id,
        name,
        avatar: (*DEFAULT_PFP_ASSET_ID).clone(),
        members,
        invite_code
    };

    Ok(group)
}

#[route("groups.join")] // TODO: notify other users about this and register their conversation keys
pub async fn join_new_group(ctx: &mut EchoContext) -> RouteResult<Group> {
    let invite_code: String = ctx
        .stream
        .receive()
        .await
        .context(E::InvalidData)?;

    let group_id: Option<SnowflakeID> = fetch_opt_scalar!(
        &ctx.pool,
        "SELECT id FROM groups WHERE invite_code = $1",
        &invite_code
    );

    let Some(id) = group_id else {
        bail!(E::Group(G::GroupNotFound));
    };

    let user = ctx.user.unwrap();

    let maybe_ban_entry: Option<i32> = fetch_opt_scalar!(
        &ctx.pool,
        "SELECT 1 FROM group_members_banned WHERE group_id = $1 AND user_id = $2",
        group_id,
        user
    );

    if maybe_ban_entry.is_some() {
        bail!(E::Group(G::BannedFromGroup));
    }

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

#[route("groups.leave")] // TODO: notify other users about this and remove their conversation keys
pub async fn leave_group(ctx: &mut EchoContext) -> RouteResult<()> {
    let user = ctx.user.unwrap();

    let group_id: SnowflakeID = ctx
        .stream
        .receive()
        .await
        .context(E::InvalidData)?;

    let stmt = "
        DELETE FROM group_members
        WHERE group_id = $1
        AND user_id = $2
        RETURNING 1
    ";

    let was_removed: Option<i32> = fetch_opt_scalar!(&ctx.pool, stmt, group_id, user);

    if was_removed.is_none() {
        bail!(E::Group(G::GroupNotFound));
    }

    Ok(())
}

#[route("groups.invite.get")]
pub async fn get_group_invite_code(ctx: &mut EchoContext) -> RouteResult<String> {
    let user = ctx.user.unwrap();

    let group_id: SnowflakeID = ctx
        .stream
        .receive()
        .await
        .context(E::InvalidData)?;

    let stmt = "
        SELECT invite_code FROM groups
        WHERE id = $1
        AND EXISTS(
            SELECT 1 FROM group_members
            WHERE group_id = $1
            AND user_id = $2
        )
    ";

    let invite_code: Option<String> = fetch_opt_scalar!(
        &ctx.pool,
        stmt,
        group_id,
        user
    );

    let Some(code) = invite_code else {
        bail!(E::Group(G::GroupNotFound));
    };

    Ok(code)
}

async fn get_group_owner(
    ctx: &mut EchoContext,
    group_id: SnowflakeID
) -> RouteResult<SnowflakeID> {
    let stmt = "
        SELECT user_id FROM group_members
        WHERE group_id = $1
        ORDER BY joined_at
        LIMIT 1
    ";

    let user_id = fetch_one_scalar!(&ctx.pool, stmt, group_id);

    Ok(user_id)
}

#[route("groups.invite.rotate")]
pub async fn rotate_group_invite_code(ctx: &mut EchoContext) -> RouteResult<String> {
    let user = ctx.user.unwrap();

    let group_id: SnowflakeID = ctx
        .stream
        .receive()
        .await
        .context(E::InvalidData)?;

    if user != get_group_owner(ctx, group_id).await? {
        bail!(E::Group(G::OnlyForOwner));
    }

    let stmt = "
        SELECT 1 FROM conversation_members
        WHERE conversation_id = $1
        AND user_id = $2
    ";

    let mut tx = ctx
        .pool
        .begin()
        .await
        .context(E::Database)?;

    let row: Option<i32> = fetch_opt_scalar!(
        &mut *tx,
        stmt,
        group_id,
        user
    );

    if row.is_none() {
        bail!(E::Group(G::GroupNotFound));
    }

    let is_code_valid = async |code: &str| -> RouteResult<bool> {
        let stmt = "
            SELECT 1 FROM groups
            WHERE id = $1
            AND invite_code = $2
        ";

        let row: Option<i32> = fetch_opt_scalar!(
            &ctx.pool,
            stmt,
            group_id,
            code
        );

        Ok(row.is_some())
    };

    let new_invite_code = loop {
        let code = generate_random_invite_code();

        if is_code_valid(&code).await? {
            break code;
        }
    };

    execute!(
        &mut *tx,
        "UPDATE groups SET invite_code = $2 WHERE id = $1",
        group_id,
        &new_invite_code
    );

    tx.commit().await.context(E::Database)?;

    Ok(new_invite_code)
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct RemoveGroupMemberData {
    pub group_id: SnowflakeID,
    pub member_id: SnowflakeID
}

#[route("groups.members.kick")]
pub async fn kick_group_member(ctx: &mut EchoContext) -> RouteResult<()> {
    let user = ctx.user.unwrap();

    let RemoveGroupMemberData {
        group_id,
        member_id
    } = ctx
        .stream
        .receive()
        .await
        .context(E::InvalidData)?;

    if user != get_group_owner(ctx, group_id).await? {
        bail!(E::Group(G::OnlyForOwner));
    }

    if user == member_id {
        bail!(E::Group(G::NotForOwner));
    }

    execute!(
        &ctx.pool,
        "DELETE FROM conversation_members WHERE conversation_id = $1 AND user_id = $2",
        group_id,
        member_id
    );

    Ok(())
}

#[route("groups.members.ban")]
pub async fn ban_group_member(ctx: &mut EchoContext) -> RouteResult<()> {
    let user = ctx.user.unwrap();

    let RemoveGroupMemberData {
        group_id,
        member_id
    } = ctx
        .stream
        .receive()
        .await
        .context(E::InvalidData)?;

    if user != get_group_owner(ctx, group_id).await? {
        bail!(E::Group(G::OnlyForOwner));
    }

    if user == member_id {
        bail!(E::Group(G::NotForOwner));
    }

    let mut tx = ctx
        .pool
        .begin()
        .await
        .context(E::Database)?;

    execute!(
        &mut *tx,
        "DELETE FROM group_members WHERE group_id = $1 AND user_id = $2",
        group_id,
        member_id
    );

    execute!(
        &mut *tx,
        "INSERT INTO group_members_banned (group_id, user_id) VALUES ($1, $2)",
        group_id,
        member_id
    );

    tx.commit().await.context(E::Database)?;

    Ok(())
}

#[route("groups.members.unban")]
pub async fn unban_group_member(ctx: &mut EchoContext) -> RouteResult<()> {
    let user = ctx.user.unwrap();

    let RemoveGroupMemberData {
        group_id,
        member_id
    } = ctx
        .stream
        .receive()
        .await
        .context(E::InvalidData)?;

    if user != get_group_owner(ctx, group_id).await? {
        bail!(E::Group(G::OnlyForOwner));
    }

    if user == member_id {
        bail!(E::Group(G::NotForOwner));
    }

    let mut tx = ctx
        .pool
        .begin()
        .await
        .context(E::Database)?;

    execute!(
        &mut *tx,
        "DELETE FROM group_members_banned WHERE group_id = $1 AND user_id = $2",
        group_id,
        member_id
    );

    tx.commit().await.context(E::Database)?;

    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EditGroupMetadataData {
    group_id: SnowflakeID,
    new_name: Option<String>,
    new_avatar: Option<AssetID>
}

#[route("groups.metadata.edit")]
pub async fn edit_group_metadata(ctx: &mut EchoContext) -> RouteResult<()> {
    let EditGroupMetadataData {
        group_id,
        new_name,
        new_avatar
    } = ctx
        .stream
        .receive()
        .await?;

    let user = ctx.user.unwrap();

    if get_group_owner(ctx, group_id).await? != user {
        bail!(E::Group(G::OnlyForOwner));
    }

    let mut tx = ctx
        .pool
        .begin()
        .await
        .context(E::Database)?;

    if let Some(name) = new_name {
        execute!(
            &mut *tx,
            "UPDATE groups SET name = $2 WHERE conversation_id = $1",
            group_id,
            name
        );
    }

    if let Some(avatar) = new_avatar {
        execute!(
            &mut *tx,
            "UPDATE groups SET name = $2 WHERE conversation_id = $1",
            group_id,
            avatar
        );
    }

    tx.commit().await.context(E::Database)?;

    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SendGroupMessageData {
    pub group_id: SnowflakeID,
    pub replied_to: Option<SnowflakeID>,
    pub message_body: Encrypted<MessageBody>,
    pub message_key: MegolmMessage
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EncryptedMegolmSession {
    pub outbound: Encrypted<GroupSessionPickle>,
    pub inbounds: HashMap<SnowflakeID, CryptoBox<SessionKey>>
}

#[route("groups.sessions.ensure")]
pub async fn ensure_latest_megolm_session(ctx: &mut EchoContext) -> RouteResult<()> {
    let user = ctx.user.unwrap();

    let group_id: SnowflakeID = ctx.stream.receive().await?;

    let maybe_max_epoch: Option<i64> = fetch_one_scalar!(
        &ctx.pool,
        "SELECT MAX(epoch) FROM group_session_keys WHERE group_id = $1",
        group_id
    );

    let mut latest_keys: Vec<(SnowflakeID, Vec<u8>)> = vec![];

    if let Some(max_epoch) = maybe_max_epoch {
        let stmt = "
            SELECT recipient_id, blob FROM group_session_keys
            WHERE group_id = $1
            AND epoch = $2
            AND sender_id = $3
        ";

        latest_keys = fetch_all_as!(
            &ctx.pool,
            stmt,
            group_id,
            max_epoch,
            user
        );
    }

    let needs_uploading = latest_keys.is_empty();

    ctx.stream.send(&ok!(needs_uploading)).await?;

    let max_epoch = maybe_max_epoch.unwrap_or(0);

    if needs_uploading {
        let mut tx = ctx
            .pool
            .begin()
            .await
            .context(E::Database)?;

        let stmt = "
            SELECT
                m.user_id,
                uc.encryption_public_key
            FROM conversation_members m
            INNER JOIN users_crypto uc USING (user_id)
            WHERE m.conversation_id = $1
            AND m.user_id != $2
        ";

        let rows: Vec<(SnowflakeID, [u8; 32])> = fetch_all_as!(
            &ctx.pool,
            stmt,
            group_id,
            user
        );

        let public_keys: HashMap<SnowflakeID, PublicKey> = rows
            .into_iter()
            .map(|(id, key_bytes)| (id, PublicKey::from_bytes(key_bytes)))
            .collect();

        ctx.stream.send(&ok!(public_keys)).await?;

        let EncryptedMegolmSession {
            outbound,
            inbounds
        } = ctx.stream.receive().await?;

        let stmt = "
            INSERT INTO group_session_keys (
                group_id,
                epoch,
                sender_id,
                recipient_id,
                blob
            ) VALUES ($1, $2, $3, $4, $5)
        ";

        execute!(
            &mut *tx,
            stmt,
            group_id,
            max_epoch,
            user,
            user,
            outbound
        );

        for (recipient_id, session_key) in inbounds {
            execute!(
                &mut *tx,
                stmt,
                group_id,
                max_epoch,
                user,
                recipient_id,
                session_key
            );
        }

        tx.commit().await.context(E::Database)?;
    }
    else {
        let mut inbounds = HashMap::<SnowflakeID, CryptoBox<SessionKey>>::new();
        let mut tmp_outbound = None;

        for (recipient_id, blob) in latest_keys {
            if recipient_id == user {
                let pickle = bitcode::deserialize(&blob)
                    .context(E::Database)?;

                tmp_outbound = Some(pickle);

                continue;
            }

            let crypto_box = bitcode::deserialize(&blob)
                .context(E::Database)?;

            inbounds.insert(recipient_id, crypto_box);
        }

        let outbound = tmp_outbound
            .context(E::Database)
            .attach("no outbound session found")?;

        let data = EncryptedMegolmSession {
            outbound,
            inbounds
        };

        ctx.stream.send(&ok!(data)).await?;
    }

    Ok(())
}

#[route("groups.messages.send")]
pub async fn send_new_group_message(ctx: &mut EchoContext) -> RouteResult<Message> {
    let user = ctx.user.unwrap();

    let SendGroupMessageData {
        group_id,
        replied_to,
        message_body,
        message_key
    } = ctx
        .stream
        .receive()
        .await
        .context(E::InvalidData)?;

    let row: Option<i32> = fetch_opt_scalar!(
        &ctx.pool,
        "SELECT 1 FROM groups WHERE id = $1",
        group_id
    );

    if row.is_none() {
        bail!(E::Group(G::GroupNotFound));
    }

    let stmt = "
        SELECT 1 FROM conversation_members
        WHERE conversation_id = $1
        AND user_id = $2
    ";

    let is_member: Option<i32> = fetch_opt_scalar!(
        &ctx.pool,
        stmt,
        group_id,
        user
    );

    if is_member.is_none() {
        bail!(E::Group(G::GroupNotFound));
    }

    let stmt = "
        SELECT user_id FROM conversation_members
        WHERE conversation_id = $1
        AND user_id != $2
    ";

    let other_members: Vec<SnowflakeID> = fetch_all_scalar!(
        &ctx.pool,
        stmt,
        group_id,
        user
    );

    let maybe_max_epoch: Option<i64> = fetch_one_scalar!(
        &ctx.pool,
        "SELECT MAX(epoch) FROM group_session_keys WHERE group_id = $1",
        group_id
    );

    let max_epoch = maybe_max_epoch.unwrap_or(0);

    let stmt = "
        SELECT 1 FROM group_session_keys
        WHERE group_id = $1
        AND sender_id = $2
        AND epoch = $3
    ";

    let has_uploaded_session: Option<i32> = fetch_opt_scalar!(
        &ctx.pool,
        stmt,
        group_id,
        user,
        max_epoch
    );

    if has_uploaded_session.is_none() {
        bail!(E::Group(G::NoMegolmSession));
    }

    let mut tx = ctx
        .pool
        .begin()
        .await
        .context(E::Database)?;

    let message_id = SNOWFLAKE_GEN.next();

    let stmt = "
        INSERT INTO messages (
            id,
            parent_id,
            conversation_id,
            author_id,
            type,
            sent_at,
            blob
        ) VALUES ($1, $2, $3, $4, $5, $6, $7)
    ";

    let message_type = match replied_to {
        Some(_) => MessageType::Reply,
        None => MessageType::Normal
    };

    execute!(
        &mut *tx,
        stmt,
        message_id,
        None::<SnowflakeID>,
        group_id,
        user,
        message_type,
        Utc::now(),
        &message_body
    );

    let max_epoch: i64 = fetch_one_scalar!(
        &ctx.pool,
        "SELECT MAX(epoch) FROM group_session_keys WHERE group_id = $1",
        group_id
    );

    let stmt = "
        INSERT INTO outgoing_message_keys (
            recipient_id,
            epoch,
            message_id,
            blob
        ) VALUES ($1, $2, $3, $4)
    ";

    for user_id in other_members {
        execute!(
            &mut *tx,
            stmt,
            user_id,
            max_epoch,
            message_id,
            &message_key.to_bytes()
        );
    }

    tx.commit().await.context(E::Database)?;

    Ok(Message {
        id: message_id,
        parent: replied_to,
        body: message_body,
        attachments: vec![] // TODO: support this
    })
}

// TODO: add the following:
// * groups.delete (remove everything about a group chat)
