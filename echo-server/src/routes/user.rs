use std::sync::LazyLock;

use echo_types::{Activity, DEFAULT_PFP_ASSET_ID, Encrypted, PasswordProtected, SNOWFLAKE_GEN, Secret, SnowflakeID, User, UserState};
use regex::Regex;
use rootcause::{bail, option_ext::OptionExt, prelude::ResultExt};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{error::{RouteError as E, RouteResult}, execute, fetch_opt, fetch_opt_as, route, router::EchoContext};

/// An error that specifically occurred in one of the routes in this module.
#[derive(Clone, Copy, Debug, Deserialize, Error, Serialize)]
pub enum UserRouteError {
    #[error("invalid usernames")]
    InvalidUsername,

    #[error("username already taken")]
    UsernameAlreadyTaken,

    #[error("no user with that ID")]
    UserNotFound
}

// Regex to match a valid username
pub static VALID_USERNAME_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("^[a-zA-Z0-9_-]{3,20}$")
        .expect("failed to compile username regex")
});

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
            encrypted_secret,
            encrypted_state
        FROM users
        WHERE id = $1
    ";

    let user: User = fetch_opt_as!(&ctx.pool, stmt, user_id)
        .context(E::User(U::UserNotFound))?;

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
    pub state: Encrypted<UserState>
}

#[route("users.create")]
pub async fn create_new_user(ctx: &mut EchoContext) -> RouteResult<User> {
    let CreateNewUserData {
        username,
        secret,
        state
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
        avatar: *DEFAULT_PFP_ASSET_ID,
        activity: Activity::Online,
        about_me: String::new(),
        status: String::new(),
        secret,
        state
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
            encrypted_state
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
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
        &user.state
    );

    Ok(user)
}
