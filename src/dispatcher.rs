use std::{collections::HashMap, sync::Arc};

use tokio::sync::{Mutex, mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel}};

#[derive(Clone, Debug)]
pub enum Event {
    Type1,
    Type2,
    Type3,
    Type4
}

type Notifier = UnboundedSender<Arc<Event>>;
type Notified = UnboundedReceiver<Arc<Event>>;

#[derive(Clone, Default)]
pub struct Dispatcher {
    notifiers: Arc<Mutex<HashMap<u64, Notifier>>>
}

impl Dispatcher {
    /// Add a new ID to be notified of certain things.
    pub async fn register(&self, id: u64) -> Notified {
        let mut notifiers = self.notifiers.lock().await;

        let (notifier, notified) = unbounded_channel();

        notifiers.insert(id, notifier);

        notified
    }

    /// Stop sending events to this ID, returning whether or not
    /// the ID was receiving events originally.
    pub async fn unregister(&self, id: u64) -> bool {
        let mut notifiers = self.notifiers.lock().await;

        notifiers.remove(&id).is_some()
    }

    /// Dispatch an event to a targeted set of listeners.
    pub async fn dispatch(&self, to: impl IntoIterator<Item = u64>, event: Event) {
        let mut notifiers = self.notifiers.lock().await;

        let event = Arc::new(event);

        for id in to {
            let Some(notifier) = notifiers.get(&id) else {
                continue;
            };

            // Notify this sender about the new event.
            let result = notifier.send(event.clone());

            // No more listeners for this sender, so we can discard it.
            if result.is_err() {
                notifiers.remove(&id);
            }
        }
    }
}
