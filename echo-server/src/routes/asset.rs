use echo_types::AssetID;
use rootcause::prelude::ResultExt;

use crate::{error::{RouteError as E, RouteResult}, route, router::EchoContext};

#[route("assets.fetch")]
pub async fn fetch_asset(ctx: &mut EchoContext) -> RouteResult<Option<Vec<u8>>> {
    let id: AssetID = ctx.stream.receive().await?;

    let asset = ctx
        .asset_storage
        .try_fetch(id)
        .await
        .context(E::Database)
        .attach("while fetching asset from asset storage")?;

    Ok(asset)
}
