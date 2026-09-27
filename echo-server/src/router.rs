use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use sqlx::postgres::PgPool;

use crate::{error::{RouteError, RouteResult}, stream::Stream};

/// A route that a client can take through the API.
///
/// Upon first connection, the client can ask to go down a specific
/// route to interact with different parts of the API.
///
/// An [`EchoContext`] is supplied to the callback, so that the callback
/// can interact with things like the underlying connection and the
/// database connection pool.
#[async_trait]
pub trait EchoRoute: Send + Sync + 'static {
    /// The unique name of the route.
    fn name(&self) -> &'static str;

    /// The callback for the route itself.
    ///
    /// This is called once the client has decided that this
    /// route is what they want to interact with.
    async fn callback(&self, ctx: &mut EchoContext) -> RouteResult<()>;
}

/// Contextual information necessary for individual routes
/// to operate correctly.
pub struct EchoContext {
    pub route_name: String,
    pub pool: PgPool,
    pub stream: Stream
}

/// A mapping of route names to route objects themselves.
#[derive(Default)]
pub struct EchoRouter {
    routes: HashMap<&'static str, Arc<dyn EchoRoute>>
}

impl EchoRouter {
    /// Create a new router.
    ///
    /// This is going to be supplied with all the implemented routes
    /// for the Echo server.
    pub fn new() -> Self {
        let mut router = Self::default();

        use crate::routes::*;

        // User routes
        router.register_route(get_user);
        router.register_route(create_new_user);

        router
    }

    /// Use the following [`EchoContext`] on this router by either
    /// redirecting execution to the correct callback, or sending
    /// back an error message.
    pub async fn run_with(&self, mut ctx: EchoContext) -> RouteResult<()> {
        match self.routes.get(ctx.route_name.as_str()) {
            Some(route) => route.callback(&mut ctx).await?,
            None => {
                ctx.stream.send(&Err::<(), _>(RouteError::UnknownResource)).await?;
            }
        };

        Ok(())
    }

    /// Register a new route.
    ///
    /// # Panics
    ///
    /// If the route has a name that is already registered,
    /// this function will panic.
    pub fn register_route(&mut self, route: impl EchoRoute) {
        let name = route.name();

        if self.routes.contains_key(name) {
            panic!("route {name:?} is already registered in this router");
        }

        self.routes.insert(name, Arc::new(route));
    }
}
