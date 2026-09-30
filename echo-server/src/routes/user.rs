use echo_types::{Activity, DEFAULT_PFP_ASSET_ID, Encrypted, Friend, FriendRequest, OlmPreKeyMessage, OlmPublicKey, PasswordProtected, SNOWFLAKE_GEN, Secret, SignatureVerifier, SnowflakeID, User, UserState};
use rootcause::{bail, option_ext::OptionExt, prelude::ResultExt};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use vodozemac::{Curve25519PublicKey, olm::{AccountPickle, PreKeyMessage, SessionPickle}};

use crate::{error::{RouteError as E, RouteResult}, execute, fetch_all_as, fetch_opt, fetch_opt_as, ok, route, router::EchoContext};

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
            signature_verifier,
            olm_account
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
    pub signature_verifier: SignatureVerifier,
    pub olm_account: Encrypted<AccountPickle>,
    pub olm_public_key: Curve25519PublicKey
}

#[route("users.create")]
#[no_auth]
pub async fn create_new_user(ctx: &mut EchoContext) -> RouteResult<User> {
    let CreateNewUserData {
        username,
        secret,
        state,
        signature_verifier,
        olm_account,
        olm_public_key
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
        signature_verifier,
        olm_account,
        olm_public_key: OlmPublicKey::from(olm_public_key)
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
            signature_verifier,
            olm_account,
            olm_public_key
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
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
        &user.signature_verifier,
        &user.olm_account,
        &user.olm_public_key
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

/// Data necessary for creating a friend request. The server
/// can supply the [`Curve25519PublicKey`] of a user to save
/// on a separate fetch request.
///
/// Because Olm uses 3DH, a third set of keys, aptly titled
/// "One-Time Keys" are required for establishing a session.
/// The public part of the OTK pair is meant to be distributed,
/// while the private part is kept inside the [`Account`]. To
/// maintain atomicity, the new account state must be uploaded
/// to the server, along with the other data.
///
/// [`Account`]: vodozemac::olm::Account
#[derive(Deserialize, Serialize)]
pub struct CreateFriendRequestData {
    pub receiver: SnowflakeID,
    pub one_time_key: Curve25519PublicKey,
    pub new_account: Encrypted<AccountPickle>
}

#[route("users.friends.requests.create")]
pub async fn create_friend_request(ctx: &mut EchoContext) -> RouteResult<()> {
    let sender = ctx.user.unwrap();

    let CreateFriendRequestData {
        receiver,
        one_time_key,
        new_account
    } = ctx.stream.receive().await?;

    let mut tx = ctx
        .pool
        .begin()
        .await
        .context(E::Database)?;

    execute!(
        &mut *tx,
        "INSERT INTO friend_requests (sender, receiver, one_time_key) VALUES ($1, $2, $3)",
        sender,
        receiver,
        OlmPublicKey::from(one_time_key)
    );

    execute!(
        &mut *tx,
        "UPDATE users SET olm_account = $2 WHERE id = $1",
        sender,
        new_account
    );

    tx.commit().await.context(E::Database)?;

    Ok(())
}

/// The public keys necessary for Olm's 3DH.
///
/// These came from whoever sent the friend request.
#[derive(Deserialize, Serialize)]
pub struct FriendRequestKeys {
    pub public_key: Curve25519PublicKey,
    pub one_time_key: Curve25519PublicKey
}

/// The encrypted session opened on the receiver's client,
/// and the pre-key message to be used for the sender's
/// client to open its own session.
#[derive(Deserialize, Serialize)]
pub struct FriendRequestSessionData {
    pub session: Encrypted<SessionPickle>,
    pub pre_key_message: PreKeyMessage
}

#[route("users.friends.requests.accept")]
pub async fn accept_friend_request(ctx: &mut EchoContext) -> RouteResult<()> {
    let receiver = ctx.user.unwrap();
    let sender: SnowflakeID = ctx.stream.receive().await?;

    let stmt = "
        SELECT
            u.olm_public_key,
            req.one_time_key
        FROM friend_requests req
        INNER JOIN users u ON u.id = req.sender
        WHERE req.sender = $1
        AND req.receiver = $2
    ";

    let maybe_one_time_key: Option<(OlmPublicKey, OlmPublicKey)> = fetch_opt_as!(
        &ctx.pool,
        stmt,
        sender,
        receiver
    );

    let keys = match maybe_one_time_key {
        Some((pk, otk)) => FriendRequestKeys {
            public_key: pk.into(),
            one_time_key: otk.into()
        },
        None => bail!(E::User(U::NotFound))
    };

    ctx.stream.send(ok!(keys)).await?;

    let FriendRequestSessionData {
        session,
        pre_key_message
    } = ctx.stream.receive().await?;

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

    execute!(
        &mut *tx,
        "INSERT INTO dm_sessions (owner, other, session) VALUES ($1, $2, $3)",
        receiver,
        sender,
        session
    );

    execute!(
        &mut *tx,
        "INSERT INTO pending_dm_sessions (waiting_on, other, pre_key_msg) VALUES ($1, $2, $3)",
        sender,
        receiver,
        OlmPreKeyMessage::from(pre_key_message)
    );

    tx.commit().await.context(E::Database)?;

    Ok(())
}
