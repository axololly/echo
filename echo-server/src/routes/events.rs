use crate::{error::RouteResult, ok, route, router::EchoContext};

#[route("events")]
pub async fn listen_to_events(ctx: &mut EchoContext) -> RouteResult<()> {
    let user = ctx.user.unwrap();

    let mut receiver = ctx.dispatcher.register(user).await;

    while let Some(event) = receiver.recv().await {
        ctx.stream.send(ok!(event)).await?;
    }

    Ok(())
}
