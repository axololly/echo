use chrono::Utc;
use echo_types::{Activity, DEFAULT_PFP_ASSET_ID, Encrypted, FriendRequest, OneTimeKey, PasswordProtected, SNOWFLAKE_GEN, Secret, SignatureVerifier, SnowflakeID, User, UserCrypto, UserData, UserSettings};
use rootcause::{bail, option_ext::OptionExt, prelude::ResultExt};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use vodozemac::olm::AccountPickle;

use crate::{error::{RouteError as E, RouteResult}, execute, fetch_all_as, fetch_all_scalar, fetch_opt, fetch_opt_as, fetch_opt_scalar, route, router::EchoContext};

#[derive(Clone, Copy, Debug, Deserialize, Error, Serialize)]
pub enum UserRouteError {
    #[error("username already taken")]
    UsernameAlreadyTaken,

    #[error("no user with that ID")]
    UserNotFound,

    #[error("already sent a friend request to that user")]
    FriendRequestAlreadySent,

    #[error("cannot send a friend request to someone you are already friends with")]
    AlreadyFriends
}

use UserRouteError as U;

#[route("users.get")]
pub async fn get_user(ctx: &mut EchoContext) -> RouteResult<User> {
    let user_id: SnowflakeID = ctx // TODO: support looking up users by name
        .conn
        .receive()
        .await
        .map_err(|_| E::InvalidData)?;

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
        .context(E::User(U::UserNotFound))?;

    Ok(user)
}

#[route("users.data.get")]
pub async fn get_user_data(ctx: &mut EchoContext) -> RouteResult<UserData> {
    let user_id: SnowflakeID = ctx // TODO: support looking up users by name
        .conn
        .receive()
        .await
        .map_err(|_| E::InvalidData)?;

    let user_data: UserData = fetch_opt_as!(
        &ctx.pool,
        "SELECT olm_account, settings FROM users WHERE id = $1",
        user_id
    ).context(E::User(U::UserNotFound))?;

    Ok(user_data)
}

#[route("users.crypto.get")]
pub async fn get_user_crypto(ctx: &mut EchoContext) -> RouteResult<UserCrypto> {
    let user_id: SnowflakeID = ctx // TODO: support looking up users by name
        .conn
        .receive()
        .await
        .map_err(|_| E::InvalidData)?;

    let user_crypto: UserCrypto = fetch_opt_as!(
        &ctx.pool,
        "SELECT signature_verifier FROM users WHERE id = $1",
        user_id
    ).context(E::User(U::UserNotFound))?;

    Ok(user_crypto)
}

#[derive(Deserialize, Serialize)]
pub struct CreateNewUserData {
    pub username: String,
    pub secret: PasswordProtected<Secret>,
    pub settings: Encrypted<UserSettings>,
    pub signature_verifier: SignatureVerifier,
    pub olm_account: Encrypted<AccountPickle>
}

#[route("users.create")]
#[no_auth] // TODO: make sure this doesn't get abused
pub async fn create_new_user(ctx: &mut EchoContext) -> RouteResult<User> {
    let CreateNewUserData {
        username,
        secret,
        settings,
        signature_verifier,
        olm_account
    } = ctx
        .conn
        .receive()
        .await
        .context(E::InvalidData)?;

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
        avatar: DEFAULT_PFP_ASSET_ID.clone(),
        activity: Activity::Online,
        about_me: String::new(),
        status: String::new(),
        secret
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
            secret
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
    ";

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
        &user.secret
    );

    execute!(
        &mut *tx,
        "INSERT INTO users_data (user_id, olm_account, settings) VALUES ($1, $2, $3)",
        &user.id,
        &olm_account,
        &settings
    );

    execute!(
        &mut *tx,
        "INSERT INTO users_crypto (user_id, signature_verifier) VALUES ($1, $2)",
        &user.id,
        &signature_verifier
    );

    tx.commit().await.context(E::Database)?;

    Ok(user)
}

#[route("users.friends.get")]
pub async fn get_friends(ctx: &mut EchoContext) -> RouteResult<Vec<SnowflakeID>> {
    let stmt = "
        SELECT user1 AS id WHERE user2 = $1
        UNION ALL
        SELECT user2 AS id WHERE user1 = $1
    ";

    let friends: Vec<SnowflakeID> = fetch_all_scalar!(&ctx.pool, stmt, ctx.user.unwrap());

    Ok(friends)
}

#[route("users.friends.requests.get")]
pub async fn get_friend_requests(ctx: &mut EchoContext) -> RouteResult<Vec<FriendRequest>> {
    let requests = fetch_all_as!(
        &ctx.pool,
        "SELECT sender, one_time_key, sent_at FROM friend_requests WHERE receiver = $1",
        ctx.user.unwrap()
    );

    Ok(requests)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CreateNewFriendRequestData {
    pub recipient: SnowflakeID,
    pub one_time_key: OneTimeKey
}

#[route("users.friends.requests.create")]
pub async fn create_new_friend_request(ctx: &mut EchoContext) -> RouteResult<()> {
    let CreateNewFriendRequestData {
        recipient, // TODO: check if they're blocked
        one_time_key
    } = ctx
        .conn
        .receive()
        .await
        .context(E::InvalidData)?;

    let sender = ctx.user.unwrap();

    let maybe_already_friends: Option<i8> = fetch_opt_scalar!(
        &ctx.pool,
        "SELECT 1 FROM friendships WHERE user1 = $1 AND user2 = $2",
        sender.min(recipient),
        sender.max(recipient)
    );

    if maybe_already_friends.is_some() {
        bail!(E::User(U::AlreadyFriends));
    }

    let maybe_already_sent: Option<i8> = fetch_opt_scalar!(
        &ctx.pool,
        "SELECT 1 FROM friend_requests WHERE sender = $1 AND recipient = $2",
        sender,
        recipient
    );

    if maybe_already_sent.is_some() {
        bail!(E::User(U::FriendRequestAlreadySent));
    }

    execute!(
        &ctx.pool,
        "INSERT INTO friend_requests (sender, receiver, one_time_key, sent_at) VALUES ($1, $2, $3, $4)",
        sender,
        recipient,
        one_time_key,
        Utc::now()
    );

    Ok(())
}

#[route("users.friends.requests.accept")]
pub async fn accept_friend_request(ctx: &mut EchoContext) -> RouteResult<()> {
    let sender: SnowflakeID = ctx
        .conn
        .receive()
        .await
        .context(E::InvalidData)?;

    let recipient = ctx.user.unwrap();

    let mut tx = ctx
        .pool
        .begin()
        .await
        .context(E::Database)?;

    execute!(
        &mut *tx,
        "DELETE FROM friend_requests WHERE sender = $1 AND recipient = $2",
        sender,
        recipient
    );

    execute!(
        &mut *tx,
        "INSERT INTO friends (user1, user2, friends_since) VALUES ($1, $2, $3)",
        sender.min(recipient),
        sender.max(recipient),
        Utc::now()
    );

    tx.commit().await.context(E::Database)?;

    // TODO: start a conversation here

    Ok(())
}

// TODO: add a resource for resetting a user's password
