use echo_types::AssetID;
use rootcause::prelude::ResultExt;
use tracing::info;

use crate::{error::{RouteError as E, RouteResult}, route, router::EchoContext};

#[route("assets.get")] // TODO: allow for seeking and reading specific amounts
pub async fn get_asset(ctx: &mut EchoContext) -> RouteResult<Option<Vec<u8>>> {
    let id: AssetID = ctx.stream.receive().await?;

    info!("User is trying to fetch asset with ID {id}");

    let asset = ctx
        .asset_storage
        .try_fetch(id)
        .await
        .context(E::Database)
        .attach("while fetching asset from asset storage")?;

    if let Some(data) = &asset {
        info!("Asset found! Size: {} bytes", data.len());
    }
    else {
        info!("Asset not found.");
    }

    Ok(asset)
}

#[route("ping")]
pub async fn ping(ctx: &mut EchoContext) -> RouteResult<()> {
    Ok(())
}
