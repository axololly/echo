use echo_types::{Signed, SnowflakeID};
use rootcause::{bail, prelude::ResultExt};

use crate::{error::{RouteError as E, RouteResult}, fetch_one_scalar, routes::UserRouteError};

use crate::router::EchoContext;

pub async fn validate_user(ctx: &mut EchoContext) -> RouteResult<SnowflakeID> {
    let signed_id: Signed<SnowflakeID> = ctx
        .stream
        .receive()
        .await
        .context(E::InvalidData)?;

    let id = signed_id.value();

    let name: String = fetch_one_scalar!(
        &ctx.pool,
        "SELECT name FROM users WHERE id = $1",
        id
    );

    let vrf_public_key = ctx
        .akd
        .get_public_key()
        .await
        .context(E::Database)?;

    let verifier = ctx
        .akd
        .single_lookup(id)
        .await
        .context(E::Database)?
        .verify(id, vrf_public_key.as_bytes())
        .context(E::Database)?
        .signature_verifier;

    println!("[ authenticating as: {name} (resource: {:?}) -> {} ]", ctx.resource, signed_id.verify(verifier));

    if !signed_id.verify(verifier) {
        bail!(E::User(UserRouteError::AuthFailed));
    }

    Ok(*id)
}
