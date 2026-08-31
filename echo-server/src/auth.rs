use echo_types::{SignatureVerifier, Signed, SnowflakeID};
use rootcause::{bail, prelude::ResultExt};

use crate::{error::{RouteError as E, RouteResult}, fetch_one_scalar};

use crate::router::EchoContext;

pub async fn validate_user(ctx: &mut EchoContext) -> RouteResult<SnowflakeID> {
    let signed_id: Signed<SnowflakeID> = ctx
        .stream
        .receive()
        .await
        .context(E::InvalidData)?;

    let id = signed_id.value();

    let verifier: SignatureVerifier = fetch_one_scalar!(
        &ctx.pool,
        "SELECT signature_verifier FROM users WHERE id = ?",
        id
    );

    if !signed_id.verify(id, verifier) {
        bail!(E::UserAuthFailed);
    }

    Ok(*id)
}
