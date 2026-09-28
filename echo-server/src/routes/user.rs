use echo_types::{Activity, DEFAULT_PFP_ASSET_ID, Encrypted, Friend, FriendRequest, PasswordProtected, SNOWFLAKE_GEN, Secret, SignatureVerifier, SnowflakeID, User, UserState};
use rootcause::{bail, option_ext::OptionExt, prelude::ResultExt};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{error::{RouteError as E, RouteResult}, execute, exists, fetch_all_as, fetch_opt, fetch_opt_as, route, router::EchoContext};

/// An error that specifically occurred in one of these
#[derive(Clone, Copy, Debug, Deserialize, Error, Serialize)]
pub enum UserRouteError {
    #[error("authentication failed")]
    AuthenticationFailed,

    #[error("username already taken")]
    UsernameAlreadyTaken,

    #[error("whatever was requested could not be found")]
    NotFound
}

use UserRouteError as U;

#[route("users.get")]
#[no_auth]
pub async fn get_user(ctx: &mut EchoContext) -> RouteResult<User> {
    let user_id: SnowflakeID = ctx // TODO: support looking up users by name
        .stream
        .receive()
        .await?;

    let stmt = "
        SELECT
            id,
            name,
            display_name,
            avatar,
            activity,
            about_me,
            status,
            encrypted_secret,
            encrypted_state,
            signature_verifier
        FROM users
        WHERE id = $1
    ";

    let user: User = fetch_opt_as!(&ctx.pool, stmt, user_id)
        .context(E::User(U::NotFound))?;

    Ok(user)
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
    pub signature_verifier: SignatureVerifier
}

#[route("users.create")]
#[no_auth]
pub async fn create_new_user(ctx: &mut EchoContext) -> RouteResult<User> {
    let CreateNewUserData {
        username,
        secret,
        state,
        signature_verifier
    } = ctx
        .stream
        .receive()
        .await?;

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
        avatar: *DEFAULT_PFP_ASSET_ID,
        activity: Activity::Online,
        about_me: String::new(),
        status: String::new(),
        secret,
        state,
        signature_verifier
    };

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
            encrypted_state,
            signature_verifier
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
    ";

    // Add the user account to the database.
    execute!(
        &ctx.pool,
        stmt,
        &user.id,
        &user.name,
        &user.display_name,
        &user.avatar,
        &user.activity,
        &user.about_me,
        &user.status,
        &user.secret,
        &user.state,
        &user.signature_verifier
    );

    Ok(user)
}

#[route("users.friends.get")]
pub async fn get_user_friends(ctx: &mut EchoContext) -> RouteResult<Vec<Friend>> {
    let stmt = r#"
        SELECT user1 AS "id", friends_since FROM friendships WHERE user2 = $1
        UNION ALL
        SELECT user2 AS "id", friends_since FROM friendships WHERE user1 = $1
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
        SELECT sender, sent_at FROM friend_requests
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

    execute!(
        &ctx.pool,
        "INSERT INTO friend_requests (sender, receiver) VALUES ($1, $2)",
        sender,
        receiver
    );

    Ok(())
}

#[route("users.friends.requests.accept")]
pub async fn accept_friend_request(ctx: &mut EchoContext) -> RouteResult<()> {
    let receiver = ctx.user.unwrap();
    let sender: SnowflakeID = ctx.stream.receive().await?;

    let friend_request_exists = exists!(
        &ctx.pool,
        "SELECT 1 FROM friend_requests WHERE sender = $1 AND receiver = $2",
        sender,
        receiver
    );

    if !friend_request_exists {
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

    execute!(
        &mut *tx,
        "INSERT INTO friendships (user1, user2) VALUES ($1, $2)",
        sender.min(receiver),
        sender.max(receiver)
    );

    tx.commit().await.context(E::Database)?;

    Ok(())
}
