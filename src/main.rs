mod dispatcher;
use dispatcher::{Dispatcher, Event};

use std::sync::Arc;

/// Register a fake listener with the given ID
/// that listens for events and notes them down.
async fn fake_listener(dispatcher: Dispatcher, id: u64) {
    let mut rx = dispatcher.register(id).await;

    tokio::spawn(async move {
        let mut received: Vec<Arc<Event>> = vec![];

        loop {
            let Some(event) = rx.recv().await else {
                break;
            };

            received.push(event);
        }

        println!("user ID {id} received: {received:?}");
    });
}

#[tokio::main]
async fn main() {
    let dispatcher = Dispatcher::default();

    let ids = [1, 2, 3];

    // Register 3 users as listeners.
    for id in ids {
        fake_listener(dispatcher.clone(), id).await;
    }

    // Dispatch a bunch of test events
    dispatcher.dispatch([1, 2, 3], Event::Type1).await;
    dispatcher.dispatch([1, 3], Event::Type2).await;
    dispatcher.dispatch([1], Event::Type3).await;
    dispatcher.dispatch([3], Event::Type4).await;

    // Drop the senders, which will close the receivers
    for id in ids {
        dispatcher.unregister(id).await;
    }
}
