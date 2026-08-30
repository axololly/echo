use echo_types::{Activity, DEFAULT_PFP_ASSET_ID, Encrypted, PasswordProtected, SNOWFLAKE_GEN, Secret, SignatureVerifier, SnowflakeID, User, UserSettings};
use rootcause::{bail, option_ext::OptionExt, prelude::ResultExt};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use vodozemac::olm::AccountPickle;

use crate::{error::{RouteError as E, RouteResult}, execute, fetch_opt, fetch_opt_as, route, router::EchoContext};

#[derive(Clone, Copy, Debug, Deserialize, Error, Serialize)]
pub enum UserRouteError {
    #[error("username already taken")]
    UsernameAlreadyTaken,

    #[error("no user with that ID")]
    UserNotFound
}

use UserRouteError as U;

#[route("users.get")]
#[ratelimit(10, 1m)]
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

#[derive(Deserialize, Serialize)]
pub struct CreateNewUserData {
    pub username: String,
    pub secret: PasswordProtected<Secret>,
    pub settings: Encrypted<UserSettings>,
    pub signature_verifier: SignatureVerifier,
    pub olm_account: Encrypted<AccountPickle>
}

#[route("users.create")]
#[ratelimit(1, 1h)]
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
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
    ";

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
        &user.secret
    );

    let stmt = "
        INSERT INTO users_crypto (
            olm_account,
            settings,
            signature_verifier
        ) VALUES ($1, $2, $3)
    ";

    execute!(
        &ctx.pool,
        stmt,
        &olm_account,
        &settings,
        &signature_verifier
    );

    Ok(user)
}
