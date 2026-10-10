use std::{collections::HashMap, ops::{Deref, DerefMut}, sync::Arc};

use echo_types::SnowflakeID;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel}};

/// An event that can be received in Echo.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Event {
    /// New friend request from a given user
    NewFriendRequest(SnowflakeID),

    /// Friend request was accepted by this user,
    /// and the receiver must supply an Olm session
    UserAcceptedFriendRequest(SnowflakeID),

    /// New DM message
    NewDirectMessageFrom(SnowflakeID)
}

type Notifier = UnboundedSender<Arc<Event>>;

/// A notification receiver, set to remove itself
/// when dropped.
pub struct Notified {
    id: SnowflakeID,
    dispatcher: EventDispatcher,
    recv: UnboundedReceiver<Arc<Event>>
}

impl Deref for Notified {
    type Target = UnboundedReceiver<Arc<Event>>;

    fn deref(&self) -> &Self::Target {
        &self.recv
    }
}

impl DerefMut for Notified {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.recv
    }
}

impl Drop for Notified {
    fn drop(&mut self) {
        let dispatcher = self.dispatcher.clone();
        let id = self.id;

        tokio::spawn(async move {
            dispatcher.unregister(id).await;
        });
    }
}

/// An event dispatcher.
#[derive(Clone, Default)]
pub struct EventDispatcher {
    notifiers: Arc<Mutex<HashMap<SnowflakeID, Notifier>>>
}

impl EventDispatcher {
    /// Add a new ID to be notified of certain things.
    pub async fn register(&self, id: SnowflakeID) -> Notified {
        let mut notifiers = self.notifiers.lock().await;

        let (sender, receiver) = unbounded_channel();

        notifiers.insert(id, sender);

        Notified {
            id,
            dispatcher: self.clone(),
            recv: receiver
        }
    }

    /// Stop sending events to this ID, returning whether or not
    /// the ID was receiving events originally.
    pub async fn unregister(&self, id: SnowflakeID) -> bool {
        let mut notifiers = self.notifiers.lock().await;

        notifiers.remove(&id).is_some()
    }

    /// Dispatch an event to a specific set of listeners.
    pub async fn dispatch(&self, to: impl IntoIterator<Item = SnowflakeID>, event: Event) {
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
