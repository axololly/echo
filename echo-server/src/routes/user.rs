use std::sync::LazyLock;

use echo_types::{Activity, BoxPublicKey, Encrypted, Friend, FriendRequest, PasswordProtected, SNOWFLAKE_GEN, Secret, SignatureVerifier, Signed, SnowflakeID, SqlxReadWatermark, User, UserDiff, UserPublicKeys, UserState};
use p256::{ecdsa::SigningKey, elliptic_curve::Generate};
use regex::Regex;
use rootcause::{bail, option_ext::OptionExt, prelude::ResultExt};
use serde::{Deserialize, Serialize};
use structdiff::StructDiff;
use thiserror::Error;

use crate::{error::{RouteError as E, RouteResult}, events::Event, execute, exists, fetch_all_as, fetch_one_as, fetch_one_scalar, fetch_opt, fetch_opt_as, fetch_opt_scalar, route, router::EchoContext};

/// An error related to users.
#[derive(Clone, Copy, Debug, Deserialize, Error, Serialize)]
pub enum UserRouteError {
    #[error("invalid usernames")]
    InvalidUsername,

    #[error("authentication failed")]
    AuthenticationFailed,

    #[error("username already taken")]
    UsernameAlreadyTaken,

    #[error("not found")]
    NotFound,

    #[error("already friends with user")]
    AlreadyFriends
}

// Regex to match a valid username
pub static VALID_USERNAME_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("^[a-zA-Z0-9_-]{3,20}$")
        .expect("failed to compile username regex")
});

use UserRouteError as U;

#[route("login")]
#[no_auth]
pub async fn login(ctx: &mut EchoContext) -> RouteResult<()> {
    let signed_id: Signed<SnowflakeID> = ctx.stream.receive().await?;

    let SignatureVerifier(verifying_key) = fetch_one_scalar!(
        &ctx.pool,
        "SELECT signature_verifier FROM users_public_keys WHERE user_id = $1",
        *signed_id
    );

    if signed_id.verify(verifying_key) {
        ctx.user = Some(*signed_id);
    }
    else {
        bail!(E::User(U::AuthenticationFailed));
    }

    Ok(())
}

#[route("users.get")]
pub async fn get_user(ctx: &mut EchoContext) -> RouteResult<User> {
    let user_id: SnowflakeID = ctx // TODO: support looking up users by name
        .stream
        .receive()
        .await?;

    let user: User = fetch_opt_as!(
        &ctx.pool,
        "SELECT * FROM users WHERE id = $1",
        user_id
    ).context(E::User(U::NotFound))?;

    Ok(user)
}

#[route("users.keys.public.get")]
pub async fn get_user_public_keys(ctx: &mut EchoContext) -> RouteResult<UserPublicKeys> {
    let user_id: SnowflakeID = ctx // TODO: support looking up users by name
        .stream
        .receive()
        .await?;

    let stmt = "
        SELECT
            signature_verifier,
            box_public_key
        FROM users_public_keys
        WHERE user_id = $1
    ";

    let user_public_keys: UserPublicKeys = fetch_opt_as!(&ctx.pool, stmt, user_id)
        .context(E::User(U::NotFound))?;

    Ok(user_public_keys)
}

/// Data related to creating a new user.
///
/// The client is responsible for generating their
/// own secret and using it responsibly.
#[derive(Deserialize, Serialize)]
pub struct CreateNewUserData {
    pub username: String,
    pub secret: PasswordProtected<Secret>,
    pub state: Encrypted<UserState>,
    pub signature_verifier: SignatureVerifier,
    pub box_public_key: BoxPublicKey
}

#[route("users.create")]
#[no_auth]
pub async fn create_new_user(ctx: &mut EchoContext) -> RouteResult<User> {
    let CreateNewUserData {
        username,
        secret,
        state,
        signature_verifier,
        box_public_key
    } = ctx
        .stream
        .receive()
        .await?;

    if !VALID_USERNAME_REGEX.is_match(&username) {
        bail!(E::User(U::InvalidUsername));
    }

    // Check if the username is already taken
    let row = fetch_opt!(
        &ctx.pool,
        "SELECT 1 FROM users WHERE name = $1",
        &username
    );

    if row.is_some() {
        bail!(E::User(U::UsernameAlreadyTaken));
    }

    let id = SNOWFLAKE_GEN.next();

    let user = User {
        id,
        name: username.clone(),
        display_name: username,
        avatar: None,
        activity: Activity::Online,
        about_me: String::new(),
        status: String::new(),
        secret,
        state
    };

    let mut tx = ctx
        .pool
        .begin()
        .await
        .context(E::Database)?;

    let stmt = "
        INSERT INTO users (
            id,
            name,
            display_name,
            avatar,
            activity,
            about_me,
            status,
            encrypted_secret,
            encrypted_state
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
    ";

    // Add the user account to the database.
    execute!(
        &mut *tx,
        stmt,
        &user.id,
        &user.name,
        &user.display_name,
        &user.avatar,
        &user.activity,
        &user.about_me,
        &user.status,
        &user.secret,
        &user.state
    );

    let stmt = "
        INSERT INTO users_public_keys (
            user_id,
            signature_verifier,
            box_public_key
        ) VALUES ($1, $2, $3)
    ";

    execute!(
        &mut *tx,
        stmt,
        user.id,
        signature_verifier,
        box_public_key
    );

    tx.commit().await.context(E::Database)?;

    Ok(user)
}

pub static VALID_DISPLAY_NAME_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^[^\p{Cc}]{1,30}$"#)
        .expect("failed to compile display name regex")
});

#[route("users.update")]
pub async fn update_user_account(ctx: &mut EchoContext) -> RouteResult<()> {
    let diffs: Vec<UserDiff> = ctx.stream.receive().await?;

    if diffs.is_empty() {
        return Ok(());
    }

    let old: User = fetch_one_as!(
        &ctx.pool,
        "SELECT * FROM users WHERE id = $1",
        ctx.user.unwrap()
    );

    let new = old.apply_ref(diffs);

    if new.name != old.name {
        if !VALID_USERNAME_REGEX.is_match(&new.name) {
            bail!(E::InvalidData);
        }

        let username_taken = exists!(
            &ctx.pool,
            "SELECT 1 FROM users WHERE name = $1",
            &new.name
        );

        if username_taken {
            bail!(E::User(U::UsernameAlreadyTaken));
        }
    }

    if new.id != old.id {
        bail!(E::InvalidData);
    }

    if !VALID_DISPLAY_NAME_REGEX.is_match(&new.display_name) {
        bail!(E::InvalidData);
    }

    if new.status.chars().count() >= 200 {
        bail!(E::InvalidData);
    }

    if new.about_me.chars().count() >= 2000 {
        bail!(E::InvalidData);
    }

    let stmt = "
        UPDATE users
        SET
            name = $2,
            display_name = $3,
            avatar = $4,
            activity = $5,
            about_me = $6,
            status = $7,
            encrypted_secret = $8,
            encrypted_state = $9
        WHERE id = $1
    ";

    execute!(
        &ctx.pool,
        stmt,
        &new.id,
        &new.name,
        &new.display_name,
        &new.avatar,
        &new.activity,
        &new.about_me,
        &new.status,
        &new.secret,
        &new.state
    );

    ctx.profile_update_pubsub.publish(ctx.user.unwrap());

    Ok(())
}

#[route("users.updates.subscribe")]
pub async fn subscribe_to_profile_updates(ctx: &mut EchoContext) -> RouteResult<()> {
    let interested_in: Vec<SnowflakeID> = ctx.stream.receive().await?;

    for id in interested_in {
        ctx.profile_update_pubsub.subscribe(ctx.user.unwrap(), id);
    }

    Ok(())
}

#[route("users.updates.unsubscribe")]
pub async fn unsubscribe_from_profile_updates(ctx: &mut EchoContext) -> RouteResult<()> {
    let not_interested_in: Vec<SnowflakeID> = ctx.stream.receive().await?;

    for id in not_interested_in {
        ctx.profile_update_pubsub.unsubscribe(ctx.user.unwrap(), id);
    }

    Ok(())
}

#[route("users.updates.unsubscribe.all")]
pub async fn unsubscribe_from_all_profile_updates(ctx: &mut EchoContext) -> RouteResult<()> {
    ctx.profile_update_pubsub.unsubscribe_all(ctx.user.unwrap());

    Ok(())
}

#[route("users.delete")]
pub async fn delete_user_account(ctx: &mut EchoContext) -> RouteResult<()> {
    let delete_all_data: bool = ctx.stream.receive().await?;

    if delete_all_data {
        execute!(
            &ctx.pool,
            "DELETE FROM users WHERE id = $1",
            ctx.user.unwrap()
        );
    }
    else {
        let valid = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

        let extension: String = rand::random_iter::<u8>()
            .take(14)
            .map(|idx| idx as usize)
            .map(|idx| char::from(valid[idx % valid.len()]))
            .collect();

        let stmt = "
            UPDATE users
            SET
                name = $2,
                display_name = 'Deleted Account',
                status = '',
                about_me = 'This account has been deleted by the user.',
                activity = 'Offline',
                avatar = NULL,
                encrypted_secret = $3
            WHERE id = $1
        ";

        let fake_verifier: SignatureVerifier = (*SigningKey::generate().verifying_key()).into();

        let mut tx = ctx
            .pool
            .begin()
            .await
            .context(E::Database)?;

        execute!(
            &mut *tx,
            stmt,
            ctx.user.unwrap(),
            format!("deleted.account.{extension}"),
            Vec::<u8>::new()
        );

        execute!(
            &mut *tx,
            "UPDATE users_public_keys SET signature_verifier = $2 WHERE user_id = $1",
            ctx.user.unwrap(),
            fake_verifier
        );

        tx.commit().await.context(E::Database)?;
    }

    ctx.user = None;

    Ok(())
}

#[route("users.friends.get")]
pub async fn get_user_friends(ctx: &mut EchoContext) -> RouteResult<Vec<Friend>> {
    let stmt = r#"
        SELECT
            f.user1 AS "user_id",
            f.friends_since,
            f.conversation_id,
            cm.last_message_id_read,
            cm.last_message_read_at
        FROM friendships f
        INNER JOIN conversation_members cm
            ON cm.conversation_id = f.conversation_id
            AND cm.user_id = f.user1
        WHERE f.user2 = $1

        UNION ALL

        SELECT
            f.user2 AS "user_id",
            f.friends_since,
            f.conversation_id,
            cm.last_message_id_read,
            cm.last_message_read_at
        FROM friendships f
        INNER JOIN conversation_members cm
            ON cm.conversation_id = f.conversation_id
            AND cm.user_id = f.user2
        WHERE f.user1 = $1
    "#;

    let user_id = ctx.user.unwrap();

    let raw_friends: Vec<_> = fetch_all_as!(
        &ctx.pool,
        stmt,
        user_id
    );

    let friends = raw_friends
        .into_iter()
        .map(|(user_id, friends_since, conversation_id, last_id, read_at)| Friend {
            user_id,
            friends_since,
            conversation_id,
            read_watermark: SqlxReadWatermark {
                last_message_id_read: last_id,
                last_message_read_at: read_at
            }.convert()
        })
        .collect();

    Ok(friends)
}

#[route("users.friends.remove")]
pub async fn remove_friend(ctx: &mut EchoContext) -> RouteResult<()> {
    let user = ctx.user.unwrap();
    let target: SnowflakeID = ctx.stream.receive().await?;

    let mut tx = ctx
        .pool
        .begin()
        .await
        .context(E::Database)?;

    let stmt = "
        DELETE FROM friendships
        WHERE user1 = $1
        AND user2 = $2
        RETURNING conversation_id
    ";

    let data: Option<SnowflakeID> = fetch_opt_scalar!(
        &mut *tx,
        stmt,
        user.min(target),
        user.max(target)
    );

    let Some(conversation_id) = data else {
        bail!(E::User(U::NotFound));
    };

    execute!(
        &mut *tx,
        "DELETE FROM conversations WHERE id = $1",
        conversation_id
    );

    tx.commit().await.context(E::Database)?;

    ctx.dispatcher.dispatch(
        [target],
        Event::NoLongerFriendsWith(user)
    );

    Ok(())
}

#[route("users.friends.requests.get")]
pub async fn get_friend_requests(ctx: &mut EchoContext) -> RouteResult<Vec<FriendRequest>> {
    let stmt = "
        SELECT
            sender,
            sent_at
        FROM friend_requests
        WHERE receiver = $1
    ";

    let user_id = ctx.user.unwrap();

    let friend_requests: Vec<FriendRequest> = fetch_all_as!(
        &ctx.pool,
        stmt,
        user_id
    );

    Ok(friend_requests)
}

#[route("users.friends.requests.create")]
pub async fn create_friend_request(ctx: &mut EchoContext) -> RouteResult<()> {
    let sender = ctx.user.unwrap();

    let receiver: SnowflakeID = ctx.stream.receive().await?;

    if sender == receiver {
        bail!(E::InvalidData);
    }

    let user_exists = exists!(
        &ctx.pool,
        "SELECT 1 FROM users WHERE id = $1",
        receiver
    );

    if !user_exists {
        bail!(E::User(U::NotFound));
    };

    let stmt = "
        SELECT 1 FROM friendships WHERE user1 = $1 AND user2 = $1
        UNION ALL
        SELECT 1 FROM friendships WHERE user2 = $1 AND user1 = $2
    ";

    let already_friends = exists!(
        &ctx.pool,
        stmt,
        sender,
        receiver
    );

    if already_friends {
        bail!(E::User(U::AlreadyFriends));
    }

    execute!(
        &ctx.pool,
        "INSERT INTO friend_requests (sender, receiver) VALUES ($1, $2)",
        sender,
        receiver
    );

    ctx.dispatcher.dispatch(
        [receiver],
        Event::NewFriendRequest(sender)
    );

    Ok(())
}

#[route("users.friends.requests.accept")]
pub async fn accept_friend_request(ctx: &mut EchoContext) -> RouteResult<SnowflakeID> {
    let receiver = ctx.user.unwrap();
    let sender: SnowflakeID = ctx.stream.receive().await?;

    let request_exists = exists!(
        &ctx.pool,
        "SELECT 1 FROM friend_requests WHERE sender = $1 AND receiver = $2",
        sender,
        receiver
    );

    if !request_exists {
        bail!(E::User(U::NotFound));
    }

    let mut tx = ctx
        .pool
        .begin()
        .await
        .context(E::Database)?;

    execute!(
        &mut *tx,
        "DELETE FROM friend_requests WHERE sender = $1 AND receiver = $2",
        sender,
        receiver
    );

    let conversation_id = SNOWFLAKE_GEN.next();

    execute!(
        &mut *tx,
        "INSERT INTO conversations (id) VALUES ($1)",
        conversation_id
    );

    execute!(
        &mut *tx,
        "INSERT INTO friendships (user1, user2, conversation_id) VALUES ($1, $2, $3)",
        sender.min(receiver),
        sender.max(receiver),
        conversation_id
    );

    for user_id in [sender, receiver] {
        execute!(
            &mut *tx,
            "INSERT INTO conversation_members (conversation_id, user_id) VALUES ($1, $2)",
            conversation_id,
            user_id
        );
    }

    tx.commit().await.context(E::Database)?;

    ctx.dispatcher.dispatch(
        [sender],
        Event::UserAcceptedFriendRequest(receiver)
    );

    Ok(conversation_id)
}

#[route("users.friends.requests.decline")]
pub async fn decline_friend_request(ctx: &mut EchoContext) -> RouteResult<()> {
    let receiver = ctx.user.unwrap();
    let sender: SnowflakeID = ctx.stream.receive().await?;

    let friend_request_exists = exists!(
        &ctx.pool,
        "DELETE FROM friend_requests WHERE sender = $1 AND receiver = $2 RETURNING 1",
        sender,
        receiver
    );

    if !friend_request_exists {
        bail!(E::User(U::NotFound));
    }

    Ok(())
}

#[route("users.friends.requests.cancel")]
pub async fn cancel_friend_request(ctx: &mut EchoContext) -> RouteResult<()> {
    let sender: SnowflakeID = ctx.user.unwrap();
    let receiver: SnowflakeID = ctx.stream.receive().await?;

    let friend_request_exists = exists!(
        &ctx.pool,
        "DELETE FROM friend_requests WHERE sender = $1 AND receiver = $2 RETURNING 1",
        sender,
        receiver
    );

    if !friend_request_exists {
        bail!(E::User(U::NotFound));
    }

    Ok(())
}
