use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use rootcause::Result;

use crate::stream::Stream;

#[async_trait]
pub trait Route: Send + Sync {
    fn name(&self) -> &'static str;

    async fn callback(&self, stream: Stream) -> Result<()>;
}

#[derive(Default)]
pub struct Router {
    routes: HashMap<&'static str, Arc<dyn Route>>
}

impl Router {
    pub fn register(&mut self, route: impl Route + 'static) {
        let name = route.name();

        if self.routes.contains_key(&name) {
            panic!("another route already has the name {name:?}");
        }

        self.routes.insert(name, Arc::new(route));
    }

    pub fn get_route(&self, name: &str) -> Option<Arc<dyn Route>> {
        self.routes.get(&name).cloned()
    }
}
