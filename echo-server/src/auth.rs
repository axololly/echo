use echo_types::{SignatureVerifier, Signed, SnowflakeID};
use rootcause::{bail, prelude::ResultExt};

use crate::{error::{RouteError as E, RouteResult}, fetch_one_scalar, router::EchoContext, routes::UserRouteError as U};

pub async fn validate_user(ctx: &mut EchoContext) -> RouteResult<()> {
    let signed_id: Signed<SnowflakeID> = ctx.stream.receive().await?;

    let SignatureVerifier(verifying_key) = fetch_one_scalar!(
        &ctx.pool,
        "SELECT signature_verifier FROM users WHERE id = $1",
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
