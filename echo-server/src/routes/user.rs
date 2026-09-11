use std::collections::HashMap;

use chrono::Utc;
use echo_akd::EchoLookupProof;
use echo_types::{Activity, CryptoBox, DEFAULT_PFP_ASSET_ID, Encrypted, FriendRequest, OneTimeKey, PasswordProtected, SNOWFLAKE_GEN, Secret, SignatureVerifier, SnowflakeID, SqlxMegolmMessage, SqlxOlmMessage, User, UserCrypto, UserData, UserSettings};
use rootcause::{bail, option_ext::OptionExt, prelude::ResultExt};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use vodozemac::{Curve25519PublicKey, megolm::{MegolmMessage, SessionKey}, olm::{AccountPickle, OlmMessage, SessionPickle}};

use crate::{error::{RouteError as E, RouteResult}, execute, fetch_all_as, fetch_all_scalar, fetch_opt, fetch_opt_as, fetch_opt_scalar, ok, route, router::EchoContext};

#[derive(Clone, Copy, Debug, Deserialize, Error, Serialize)]
pub enum UserRouteError {
    #[error("user failed to authenticate themselves")]
    AuthFailed,

    #[error("username already taken")]
    UsernameAlreadyTaken,

    #[error("no user with that ID")]
    UserNotFound,

    #[error("already sent a friend request to that user")]
    FriendRequestAlreadySent,

    #[error("friend request not found")]
    FriendRequestNotFound,

    #[error("cannot send a friend request to someone you are already friends with")]
    AlreadyFriends
}

use UserRouteError as U;

#[route("users.get")]
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
            secret
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
        .stream
        .receive()
        .await?;

    let user_data: UserData = fetch_opt_as!(
        &ctx.pool,
        "SELECT settings FROM users_data WHERE id = $1",
        user_id
    ).context(E::User(U::UserNotFound))?;

    Ok(user_data)
}

#[derive(Deserialize, Serialize)]
pub struct CreateNewUserData {
    pub username: String,
    pub secret: PasswordProtected<Secret>,
    pub settings: Encrypted<UserSettings>,
    pub signature_verifier: SignatureVerifier,
    pub encryption_public_key: crypto_box::PublicKey,
    pub olm_account: Encrypted<AccountPickle>,
    pub olm_one_time_keys: Vec<Curve25519PublicKey>
}

#[route("users.create")]
#[no_auth] // TODO: make sure this doesn't get abused
pub async fn create_new_user(ctx: &mut EchoContext) -> RouteResult<User> {
    let CreateNewUserData {
        username,
        secret,
        settings,
        signature_verifier,
        encryption_public_key,
        olm_account,
        olm_one_time_keys
    } = ctx
        .stream
        .receive()
        .await?;

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
        "INSERT INTO users_data (user_id, settings, olm_account) VALUES ($1, $2, $3)",
        &user.id,
        &settings,
        &olm_account
    );

    let stmt = "INSERT INTO users_one_time_keys (user_id, one_time_key) VALUES ($1, $2)";

    for one_time_key in olm_one_time_keys {
        execute!(
            &mut *tx,
            stmt,
            user.id,
            OneTimeKey::from(one_time_key)
        );
    }

    let crypto = UserCrypto {
        signature_verifier,
        public_key: encryption_public_key
    };

    ctx
        .akd
        .insert(&id, &crypto)
        .await
        .context(E::Database)?;

    tx.commit().await.context(E::Database)?;

    Ok(user)
}

#[route("users.friends.get")]
pub async fn get_friends(ctx: &mut EchoContext) -> RouteResult<Vec<SnowflakeID>> {
    let stmt = "
        SELECT user1 AS id FROM friendships
        WHERE user2 = $1
        UNION ALL
        SELECT user2 AS id FROM friendships
        WHERE user1 = $1
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
pub async fn create_new_friend_request(ctx: &mut EchoContext) -> RouteResult<FriendRequest> {
    let CreateNewFriendRequestData {
        recipient, // TODO: check if they're blocked
        one_time_key
    } = ctx
        .stream
        .receive()
        .await?;

    let sender = ctx.user.unwrap();

    let maybe_already_friends: Option<i32> = fetch_opt_scalar!(
        &ctx.pool,
        "SELECT 1 FROM friendships WHERE user1 = $1 AND user2 = $2",
        sender.min(recipient),
        sender.max(recipient)
    );

    if maybe_already_friends.is_some() {
        bail!(E::User(U::AlreadyFriends));
    }

    let maybe_already_sent: Option<i32> = fetch_opt_scalar!(
        &ctx.pool,
        "SELECT 1 FROM friend_requests WHERE sender = $1 AND receiver = $2",
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

    let friend_request = FriendRequest {
        sender,
        one_time_key,
        sent_at: Utc::now()
    };

    Ok(friend_request)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CreateDirectMessageData {
    pub encrypted_session: Encrypted<SessionPickle>,
    pub pre_key_msg: OlmMessage
}

#[route("users.friends.requests.accept")]
pub async fn accept_friend_request(ctx: &mut EchoContext) -> RouteResult<()> {
    let sender: SnowflakeID = ctx
        .stream
        .receive()
        .await?;

    let recipient = ctx.user.unwrap();

    let is_pending_friend_request: Option<i32> = fetch_opt_scalar!(
        &ctx.pool,
        "SELECT 1 FROM friend_requests WHERE sender = $1 AND receiver = $2",
        sender,
        recipient
    );

    if is_pending_friend_request.is_none() {
        bail!(E::User(U::FriendRequestNotFound));
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
        recipient
    );

    execute!(
        &mut *tx,
        "INSERT INTO friendships (user1, user2) VALUES ($1, $2)",
        sender.min(recipient),
        sender.max(recipient)
    );

    let CreateDirectMessageData {
        encrypted_session,
        pre_key_msg
    } = ctx
        .stream
        .receive()
        .await?;

    execute!(
        &mut *tx,
        "INSERT INTO dm_sessions (owner_id, other_id, blob) VALUES ($1, $2, $3)",
        recipient,
        sender,
        encrypted_session
    );

    execute!(
        &mut *tx,
        "INSERT INTO pending_dm_sessions (owner_id, other_id, pre_key_msg) VALUES ($1, $2, $3)",
        recipient,
        sender,
        SqlxOlmMessage::from(pre_key_msg)
    );

    tx.commit().await.context(E::Database)?;

    Ok(())
}

#[route("users.reset_password")]
pub async fn reset_user_password(ctx: &mut EchoContext) -> RouteResult<()> {
    let new_secret: PasswordProtected<Secret> = ctx
        .stream
        .receive()
        .await?;

    let user = ctx.user.unwrap();

    execute!(
        &ctx.pool,
        "UPDATE users SET secret = $2 WHERE user_id = $1",
        user,
        new_secret
    );

    Ok(())
}
