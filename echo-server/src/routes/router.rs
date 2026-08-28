use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use echo_server::{connection::Connection, error::RouteError, router::{RateLimiter, Route, Router}};
use echo_types::SnowflakeID;
use rootcause::Result;
use sqlx::postgres::PgPool;

use crate::auth::validate_user;

pub struct EchoContext {
    pub resource: String,
    pub pool: PgPool,
    pub conn: Connection,
    pub user: Option<SnowflakeID>
}

pub struct EchoRouter {
    routes: HashMap<&'static str, Arc<dyn Route<EchoContext>>>,
    ratelimiter: RateLimiter
}

impl EchoRouter {
    pub async fn new() -> Self {
        let mut router = Self {
            routes: HashMap::new(),
            ratelimiter: RateLimiter::new()
        };

        use crate::{group::*, user::*};

        // Group routes
        router.register_route(create_new_group).await;

        // User routes
        router.register_route(create_new_user).await;
        router.register_route(get_user).await;

        router
    }
}

#[async_trait]
impl Router for EchoRouter {
    type Context = EchoContext;

    async fn run_with(&self, mut ctx: EchoContext) -> Result<()> {
        match self.routes.get(ctx.resource.as_str()) {
            Some(route) => {
                if route.needs_authentication() {
                    ctx.user = Some(validate_user(&mut ctx).await?);
                }

                route.callback(&mut ctx).await?;
            },

            None => {
                ctx.conn.send(&Err::<(), _>(RouteError::UnknownResource)).await?;
            }
        };

        Ok(())
    }

    async fn register_route(&mut self, route: impl Route<EchoContext>) {
        if self.routes.contains_key(route.resource()) {
            panic!("route {:?} is already registered in this router", route.resource());
        }

        self.ratelimiter.set_ratelimit(route.resource(), route.rate_limit()).await;

        self.routes.insert(route.resource(), Arc::new(route));
    }
}
