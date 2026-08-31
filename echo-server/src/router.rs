use std::{collections::{HashMap, HashSet}, sync::Arc};

use async_trait::async_trait;
use sqlx::postgres::PgPool;

use chrono::Utc;
use echo_types::SnowflakeID;
use rootcause::Result;
use tokio::sync::Mutex;

use crate::{auth::validate_user, error::{RouteError, RouteResult}, stream::Stream};

pub struct RateLimit {
    pub num_times: usize,
    pub per_secs: u64
}

pub struct RateLimitRecords {
    records: HashMap<SnowflakeID, HashSet<u64>>, // TODO: make generic so it's easy to do IP addresses too
    ratelimit: RateLimit
}

impl RateLimitRecords {
    pub fn new(ratelimit: RateLimit) -> Self {
        Self {
            records: HashMap::new(),
            ratelimit
        }
    }
}

pub struct ResourceRateLimits {
    resources: HashMap<&'static str, RateLimitRecords>,
    skip: HashSet<&'static str>
}

pub struct RateLimiter {
    inner: Arc<Mutex<ResourceRateLimits>>
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(ResourceRateLimits {
                resources: HashMap::new(),
                skip: HashSet::new()
            }))
        }
    }

    /// Set a ratelimit for a route, panicking if one already exists.
    pub async fn set_ratelimit(&self, resource: &'static str, rate_limit: Option<RateLimit>) {
        let mut inner = self.inner.lock().await;

        match rate_limit {
            Some(limit) => {
                inner.resources.insert(resource, RateLimitRecords::new(limit));
            },
            None => {
                inner.skip.insert(resource);
            }
        }
    }

    /// Add a new record to this ratelimiter and return if the
    /// ratelimit was reached or not.
    pub async fn add(&self, resource: &str, id: SnowflakeID) -> bool {
        let mut resource_rate_limits = self.inner.lock().await;

        if resource_rate_limits.skip.contains(resource) {
            return false;
        }

        let resource_records = &mut resource_rate_limits.resources;

        if !resource_records.contains_key(resource) {
            panic!("unrecognised resource {resource}");
        }

        let RateLimitRecords {
            records,
            ratelimit
        } = resource_records.get_mut(resource).unwrap();

        let timestamps = records.entry(id).or_default();

        let now = Utc::now().timestamp() as u64;

        timestamps.insert(now);

        timestamps.retain(|&ts| now - ts <= ratelimit.per_secs);

        timestamps.len() > ratelimit.num_times
    }
}

#[async_trait]
pub trait Route<Context>: Send + Sync + 'static {
    async fn callback(&self, ctx: &mut Context) -> RouteResult<()>;

    fn resource(&self) -> &'static str;

    fn rate_limit(&self) -> Option<RateLimit> {
        None
    }

    fn needs_authentication(&self) -> bool {
        true
    }
}

pub struct EchoContext {
    pub resource: String,
    pub pool: PgPool,
    pub stream: Stream,
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

        use crate::routes::*;

        // Group routes
        router.register_route(create_new_group).await;
        router.register_route(get_group).await;
        router.register_route(join_new_group).await;
        router.register_route(leave_group).await;

        // User routes
        router.register_route(create_new_user).await;
        router.register_route(get_user).await;
        router.register_route(get_user_crypto).await;
        router.register_route(get_user_data).await;
        router.register_route(get_friends).await;
        router.register_route(get_friend_requests).await;
        router.register_route(create_new_friend_request).await;
        router.register_route(accept_friend_request).await;

        router
    }

    pub async fn run_with(&self, mut ctx: EchoContext) -> Result<()> {
        match self.routes.get(ctx.resource.as_str()) {
            Some(route) => {
                if route.needs_authentication() {
                    ctx.user = Some(validate_user(&mut ctx).await?);
                }

                route.callback(&mut ctx).await?;
            },

            None => {
                ctx.stream.send(&Err::<(), _>(RouteError::UnknownResource)).await?;
            }
        };

        Ok(())
    }

    pub async fn register_route(&mut self, route: impl Route<EchoContext>) {
        if self.routes.contains_key(route.resource()) {
            panic!("route {:?} is already registered in this router", route.resource());
        }

        self.ratelimiter.set_ratelimit(route.resource(), route.rate_limit()).await;

        self.routes.insert(route.resource(), Arc::new(route));
    }
}
