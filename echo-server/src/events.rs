use std::{ops::{Deref, DerefMut}, sync::Arc};

use chrono::TimeDelta;
use dashmap::{DashMap, DashSet};
use echo_types::{AssetID, Emoji, GroupInvite, SnowflakeID};
use rootcause::prelude::ResultExt;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel}};

use crate::{error::RouteResult, fetch_all_scalar, router::EchoContext};

/// An event that can be received in Echo.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Event {
    /// New friend request from a given user
    NewFriendRequest(SnowflakeID),

    /// Friend request was accepted by this user,
    /// and the receiver must supply a DM session
    UserAcceptedFriendRequest(SnowflakeID),

    /// New message received
    NewMessageReceived {
        conversation_id: SnowflakeID,
        message_id: SnowflakeID,
        author_id: SnowflakeID
    },

    /// Unfriended by another user
    NoLongerFriendsWith(SnowflakeID),

    /// Group chat appearance updated
    GroupAppearanceUpdated {
        new_name: Option<String>,
        new_avatar: Option<AssetID>
    },

    /// Member joined the group chat
    MemberJoinedGroup {
        group_id: SnowflakeID,
        member_id: SnowflakeID
    },

    /// Member left the group chat
    MemberLeftGroup {
        group_id: SnowflakeID,
        member_id: SnowflakeID
    },

    /// Group's lock status was changed
    GroupLockStatusUpdated {
        group_id: SnowflakeID,
        locked: bool
    },

    /// New message sent in group
    GroupInviteRotated {
        group_id: SnowflakeID,
        new_invite: GroupInvite
    },

    /// New message sent in group
    NewGroupMessage {
        group_id: SnowflakeID,
        author_id: SnowflakeID,
        message_id: SnowflakeID
    },

    /// Message was pinned or unpinned
    MessagePinStatusUpdated {
        message_id: SnowflakeID,
        pinned: bool
    },

    /// Message was edited
    MessageEdited {
        conversation_id: SnowflakeID,
        message_id: SnowflakeID
    },

    /// Message was deleted
    MessageDeleted {
        conversation_id: SnowflakeID,
        message_id: SnowflakeID
    },

    /// Emoji added
    NewGroupEmoji(Emoji),

    /// Emoji deleted
    GroupEmojiDeleted(SnowflakeID),

    /// New reaction added
    NewReactionAdded {
        message_id: SnowflakeID,
        author: SnowflakeID,
        emoji_id: SnowflakeID
    },

    /// Reaction removed
    ReactionRemoved {
        message_id: SnowflakeID,
        author: SnowflakeID,
        emoji_id: SnowflakeID
    },

    /// Updated conversation timer
    ConversationTimerUpdated {
        conversation_id: SnowflakeID,
        new_message_timer: Option<TimeDelta>
    },

    /// User started typing
    UserStartedTyping {
        conversation_id: SnowflakeID,
        user_id: SnowflakeID
    }
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
        self.dispatcher.unregister(self.id);
    }
}

/// An event dispatcher.
#[derive(Clone, Default)]
pub struct EventDispatcher {
    notifiers: Arc<DashMap<SnowflakeID, Notifier>>
}

impl EventDispatcher {
    /// Add a new ID to be notified of certain things.
    pub fn register(&self, id: SnowflakeID) -> Notified {
        let (sender, receiver) = unbounded_channel();

        self.notifiers.insert(id, sender);

        Notified {
            id,
            dispatcher: self.clone(),
            recv: receiver
        }
    }

    /// Stop sending events to this ID, returning whether or not
    /// the ID was receiving events originally.
    pub fn unregister(&self, id: SnowflakeID) -> bool {
        self.notifiers.remove(&id).is_some()
    }

    /// Dispatch an event to a specific set of listeners.
    pub fn dispatch(
        &self,
        to: impl IntoIterator<Item = SnowflakeID>,
        event: Event
    ) {
        let event = Arc::new(event);

        for id in to {
            let Some(notifier) = self.notifiers.get(&id) else {
                continue;
            };

            // Notify this sender about the new event.
            let result = notifier.send(event.clone());

            // No more listeners for this sender, so we can discard it.
            if result.is_err() {
                self.notifiers.remove(&id);
            }
        }
    }

    /// Dispatch an [`Event`] that is dependent on a member's ID.
    pub fn dispatch_contextual(
        &self,
        to: impl IntoIterator<Item = SnowflakeID>,
        event_fn: impl Fn(SnowflakeID) -> Event
    ) {
        for id in to {
            let Some(notifier) = self.notifiers.get(&id) else {
                continue;
            };

            // Notify this sender about the new event.
            let result = notifier.send(Arc::new(event_fn(id)));

            // No more listeners for this sender, so we can discard it.
            if result.is_err() {
                self.notifiers.remove(&id);
            }
        }
    }
}

/// Dispatch the same [`Event`] to all current
/// members of a conversation.
pub async fn dispatch_event_for_conversation(
    ctx: &mut EchoContext,
    conversation_id: SnowflakeID,
    event: Event
) -> RouteResult<()> {
    let members: Vec<SnowflakeID> = fetch_all_scalar!(
        &ctx.pool,
        "SELECT user_id FROM conversation_members WHERE conversation_id = $1",
        conversation_id
    );

    ctx.dispatcher.dispatch(members, event);

    Ok(())
}

#[derive(Clone)]
pub struct TypingEventPubSub {
    conversational_interests: Arc<DashMap<SnowflakeID, DashSet<SnowflakeID>>>,
    user_interests: Arc<DashMap<SnowflakeID, SnowflakeID>>,
    dispatcher: EventDispatcher
}

impl TypingEventPubSub {
    pub fn with_dispatcher(dispatcher: EventDispatcher) -> Self {
        Self {
            dispatcher,
            conversational_interests: Default::default(),
            user_interests: Default::default()
        }
    }

    pub fn subscribe(&self, conversation_id: SnowflakeID, user_id: SnowflakeID) {
        let interested = self
            .conversational_interests
            .entry(conversation_id)
            .or_default();

        interested.insert(user_id);

        let prev_conv_id = self.user_interests.insert(user_id, conversation_id);

        if let Some(id) = prev_conv_id {
            self.conversational_interests
                .get(&id)
                .and_then(|interested| interested.remove(&id));
        }
    }

    pub fn unsubscribe(&self, user_id: SnowflakeID) {
        let Some((_, conversation_id)) = self.user_interests.remove(&user_id) else {
            return;
        };

        self.conversational_interests
            .get(&conversation_id)
            .and_then(|interested| interested.remove(&user_id));
    }

    pub fn publish(&self, conversation_id: SnowflakeID, user_id: SnowflakeID) {
        let Some(users) = self.conversational_interests.get(&conversation_id) else {
            return;
        };

        let users = users
            .iter()
            .map(|id| *id);

        self.dispatcher.dispatch(users, Event::UserStartedTyping {
            conversation_id,
            user_id
        });
    }
}
