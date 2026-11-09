use std::sync::LazyLock;

use echo_types::{Activity, BoxPublicKey, Encrypted, Friend, FriendRequest, PasswordProtected, SNOWFLAKE_GEN, Secret, SignatureVerifier, Signed, SnowflakeID, User, UserPublicKeys, UserState};
use regex::Regex;
use rootcause::{bail, option_ext::OptionExt, prelude::ResultExt};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{error::{RouteError as E, RouteResult}, events::Event, execute, exists, fetch_all_as, fetch_one_scalar, fetch_opt, fetch_opt_as, route, router::EchoContext};

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

    let stmt = "
        SELECT
            u.id,
            u.name,
            u.display_name,
            u.avatar,
            u.activity,
            u.about_me,
            u.status,
            u.encrypted_secret,
            u.encrypted_state,
            u.olm_account
            pk.signature_verifier,
            pk.olm_public_key
        FROM users u
        INNER JOIN users_public_keys pk ON pk.user_id = u.id
        WHERE id = $1
    ";

    let user: User = fetch_opt_as!(&ctx.pool, stmt, user_id)
        .context(E::User(U::NotFound))?;

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
            olm_public_key,
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

#[route("users.friends.get")]
pub async fn get_user_friends(ctx: &mut EchoContext) -> RouteResult<Vec<Friend>> {
    let stmt = r#"
        SELECT user1 AS "user_id", friends_since, conversation_id FROM friendships WHERE user2 = $1
        UNION ALL
        SELECT user2 AS "user_id", friends_since, conversation_id FROM friendships WHERE user1 = $1
    "#;

    let user_id = ctx.user.unwrap();

    let friends: Vec<Friend> = fetch_all_as!(
        &ctx.pool,
        stmt,
        user_id
    );

    Ok(friends)
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

    ctx
        .dispatcher
        .dispatch([receiver], Event::NewFriendRequest(sender))
        .await;

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

    ctx
        .dispatcher
        .dispatch([sender], Event::UserAcceptedFriendRequest(receiver))
        .await;

    Ok(conversation_id)
}
