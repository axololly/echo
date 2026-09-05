use akd::{HistoryProof, ecvrf::VRFPublicKey};

use echo_akd::{EchoLookupProof, SerdeEpochHash};
use echo_types::SnowflakeID;
use rootcause::prelude::ResultExt;

use crate::{error::{RouteError as E, RouteResult}, route, router::EchoContext};

#[route("akd.crypto.get")]
pub async fn get_user_crypto_with_proof(ctx: &mut EchoContext) -> RouteResult<EchoLookupProof> {
    let user_id: SnowflakeID = ctx // TODO: support looking up users by name
        .stream
        .receive()
        .await?;

    ctx
        .akd
        .single_lookup(&user_id)
        .await
        .context(E::Database)
}

#[route("akd.crypto.history.verify")]
pub async fn verify_user_crypto_history(ctx: &mut EchoContext) -> RouteResult<(HistoryProof, SerdeEpochHash)> {
    let user_id: SnowflakeID = ctx // TODO: support looking up users by name
        .stream
        .receive()
        .await?;

    let limit: Option<u64> = ctx.stream.receive().await?;

    let (proof, hash) = ctx
        .akd
        .history_lookup(&user_id, limit.map(|x| x as usize))
        .await
        .context(E::Database)?;

    Ok((proof, (hash.0, hash.1)))
}

#[route("akd.public_key.get")]
#[no_auth]
pub async fn get_akd_public_key(ctx: &mut EchoContext) -> RouteResult<VRFPublicKey> {
    let key = ctx
        .akd
        .get_public_key()
        .await
        .context(E::Database)?;

    Ok(key)
}
