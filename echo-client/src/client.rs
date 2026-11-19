use std::{collections::HashMap, ops::Deref, sync::Arc};

use chrono::{DateTime, TimeDelta, Utc};
use echo_server::{error::RouteError, events::Event, routes::{AddFriendToGroupData, AddNewReactionData, BanMemberData, CreateNewEmojiData, CreateNewGroupData, CreateNewUserData, DeleteGroupEmojiData, EditMessageData, EncryptedChatSession, GetMessageHistoryData, GroupRouteError, KickMemberData, MessageHistoryParams, MessagesRouteError, RemoveReactionData, SendMessageData, UnbanMemberData, UnprocessedMessage, UpdateDefaultMessageTimerData, UpdateGroupAppearanceData, UpdateGroupLockData, UpdateMessagePinData, UpdateReadWatermarkData, UserRouteError, UserSearchAction, UserSearchResult}, stream::Stream};
use echo_types::{AssetID, BannedMember, BoxPublicKey, Compressed, Emoji, Encrypted, Friend, FriendRequests, Group, GroupInvite, GroupMember, Message, OutgoingFriendRequest, PasswordProtected, Reaction, ReadWatermark, ReadWatermarks, Secret, SnowflakeID, UploadedAttachment, User};
use rootcause::{Result, bail, option_ext::OptionExt};
use structdiff::StructDiff;
use tokio::sync::{Mutex, MutexGuard, broadcast::{Receiver, Sender, error::RecvError}};
use vodozemac::megolm::{GroupSession, GroupSessionPickle, InboundGroupSession, SessionConfig};

use crate::{connect::{RouteResult, ServerConnection, connect_to_server}, file::File, objects::ObjectStore, secret::MasterSecret};

/// An immutable reference to a [`User`], accessed through dereferencing.
pub struct UserRef<'a>(MutexGuard<'a, User>);

impl<'a> Deref for UserRef<'a> {
    type Target = User;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub(crate) struct BaseClient {
    pub(crate) user_id: SnowflakeID,
    pub(crate) user: Mutex<User>,
    pub(crate) master_secret: MasterSecret,
    pub(crate) objects: Arc<ObjectStore>,
    pub(crate) conn: ServerConnection
}

/// The main way of interacting with the Echo API.
#[derive(Clone)]
pub struct Client {
    base: Arc<BaseClient>,
    notifier: EventNotifier
}

/// Methods for getting access to privatised base-level fields.
impl Client {
    /// Get the user account this client is logged in as.
    pub async fn user<'a>(&'a self) -> UserRef<'a> {
        UserRef(self.base.user.lock().await)
    }

    /// Get the user ID of the account this client is logged in as.
    pub fn user_id(&self) -> SnowflakeID {
        self.base.user_id
    }

    /// Get the master secret for this user account.
    pub fn master_secret(&self) -> MasterSecret {
        self.base.master_secret
    }
}

/// Methods for gaining access to the server, either by logging
/// in as an existing user, or by creating a new account.
impl Client {
    fn new(base: BaseClient) -> Self {
        let notifier = EventNotifier::new(base.conn.clone());

        let n = notifier.clone();

        tokio::spawn(async move {
            n.start().await
        });

        Self {
            base: Arc::new(base),
            notifier
        }
    }

    /// Log into a server with the given username and password.
    pub async fn login(
        username: &str,
        password: &str,
        server_addr: (&str, u16)
    ) -> Result<Self> {
        let (host, port) = server_addr;
        let conn = connect_to_server(host, port).await?;

        let (user_id, master_secret) = conn.access_route("login", async |stream| {
            stream.send(&username).await?;

            let (user_id, secret): (SnowflakeID, PasswordProtected<Secret>) = stream.receive::<RouteResult<_>>().await??;

            let master_secret: MasterSecret = secret.unlock(password)?.into();

            let signed_id = master_secret.signing_secret().sign(user_id);

            stream.send(&signed_id).await?;

            stream.receive::<RouteResult<()>>().await??;

            Ok((user_id, master_secret))
        }).await?;

        let user = conn.access_route("users.get", async |stream| {
            stream.send(&user_id).await?;

            let user = stream.receive::<RouteResult<User>>().await??;

            Ok(user)
        }).await?;

        let base_client = BaseClient {
            conn,
            user_id: user.id,
            user: Mutex::new(user),
            master_secret,
            objects: Default::default()
        };

        Ok(Self::new(base_client))
    }

    /// Create an account on the server with the given username and password.
    pub async fn create_account(
        username: &str,
        password: &str,
        server_addr: (&str, u16)
    ) -> Result<Self> {
        let (host, port) = server_addr;
        let conn = connect_to_server(host, port).await?;

        let master_secret = MasterSecret::random();

        let user = conn.access_route("users.create", async |stream| {
            stream.send(&CreateNewUserData {
                username: username.to_string(),
                secret: PasswordProtected::new(
                    &master_secret.into(),
                    password
                ),
                signature_verifier: master_secret.signing_secret().into(),
                box_public_key: master_secret.box_secret().into()
            }).await?;

            let user =  stream.receive::<RouteResult<User>>().await??;

            Ok(user)
        }).await?;

        let base_client = BaseClient {
            conn,
            user_id: user.id,
            user: Mutex::new(user),
            master_secret,
            objects: Default::default()
        };

        Ok(Self::new(base_client))
    }
}

/// A wrapper struct that filters out irrelevant event types.
pub struct Notified {
    receiver: Receiver<Arc<Event>>,
    filter: Box<dyn Fn(&Event) -> bool>
}

impl Notified {
    /// Wait for a new event, returning `None` if the
    /// channel is closed.
    pub async fn recv(&mut self) -> Option<Arc<Event>> {
        let f = &*self.filter;

        loop {
            let event = match self.receiver.recv().await {
                Ok(ev) => ev,
                Err(RecvError::Closed) => return None,
                Err(RecvError::Lagged(_)) => continue
            };

            if f(&event) {
                return Some(event);
            }
        }
    }
}

#[derive(Clone)]
pub struct EventNotifier {
    conn: ServerConnection,
    notifier: Sender<Arc<Event>>
}

impl EventNotifier {
    pub(crate) fn new(conn: ServerConnection) -> Self {
        Self {
            conn,
            notifier: Sender::new(1)
        }
    }

    /// Start the event notifier.
    pub async fn start(&self) -> Result<()> {
        let notifier = self.notifier.clone();

        self.conn.access_route::<()>("events", async move |stream| {
            loop {
                let event = stream.receive::<RouteResult<Event>>().await??;

                let _ = notifier.send(Arc::new(event));
            }
        }).await
    }

    /// Listen for a specific event or events.
    pub fn listen_for(&self, filter: impl Fn(&Event) -> bool + 'static) -> Notified {
        Notified {
            receiver: self.notifier.subscribe(),
            filter: Box::new(filter)
        }
    }
}

macro_rules! listen_for {
    ($self:expr, $($t:tt)*) => {
        $self.notifier.listen_for(|ev| matches!(ev, $($t)*))
    };
}

// Background processes to handle data.
impl Client {
    fn process_unread_message(&self, unprocessed: UnprocessedMessage) -> Result<Secret> {
        let box_secret = self.base.master_secret.box_secret();

        let UnprocessedMessage { session_key, message_key } = unprocessed;

        let session_key = box_secret.unbox(&session_key)?;

        let mut inbound = InboundGroupSession::new(
            &session_key,
            SessionConfig::version_1()
        );

        let plaintext = inbound.decrypt(&message_key)?.plaintext;

        let secret = Secret::try_from_bytes(plaintext)
            .context("invalid length for secret")?;

        Ok(secret)
    }

    async fn process_unread_messages_bulk(&self) -> Result<()> {
        let encryption_secret = self.base.master_secret.encryption_secret();

        self.base.conn.access_route("messages.unread.process.bulk", async |stream| {
            let mut unprocessed: HashMap<SnowflakeID, UnprocessedMessage>;
            let mut processed: HashMap<SnowflakeID, Encrypted<Secret>>;

            loop {
                unprocessed = stream.receive::<RouteResult<_>>().await??;

                if unprocessed.is_empty() {
                    break;
                }

                processed = HashMap::new();

                for (id, unprocessed) in unprocessed {
                    if let Ok(message_secret) = self.process_unread_message(unprocessed) {
                        self.base.objects.messages.secrets.insert(id, message_secret);

                        processed.insert(id, encryption_secret.encrypt(&message_secret));
                    }
                }

                stream.send(&processed).await?;
            }

            Ok(())
        }).await
    }

    async fn process_unread_messages_one_by_one(&self, message_id: SnowflakeID) -> Result<()> {
        let encryption_secret = self.base.master_secret.encryption_secret();

        self.base.conn.access_route("messages.unread.process.one", async |stream| {
            stream.send(&message_id).await?;

            let Some(unprocessed) = stream.receive::<RouteResult<_>>().await?? else {
                return Ok(());
            };

            let message_secret = self
                .process_unread_message(unprocessed)
                .inspect(|&secret| {
                    self.base.objects.messages.secrets.insert(message_id, secret);
                })
                .map(|secret| encryption_secret.encrypt(&secret))
                .ok();

            stream.send(&message_secret).await?;

            stream.receive::<RouteResult<()>>().await??;

            Ok(())
        }).await
    }

    /// Initially try to process messages in bulk, then incrementally process single
    /// messages that flow through by listening to their events.
    pub async fn process_messages_in_background(&self) -> Result<()> {
        self.process_unread_messages_bulk().await?;

        let mut listener = listen_for!(self, Event::NewMessageReceived { .. });

        let conversations = &self.base.objects.conversations.messages;

        while let Some(ev) = listener.recv().await
            && let Event::NewMessageReceived { message_id, conversation_id, .. } = *ev
        {
            self.process_unread_messages_one_by_one(message_id).await?;

            conversations
                .entry(conversation_id)
                .or_default()
                .insert(message_id);
        }

        Ok(())
    }

    /// Update metadata on locally stored message objects for the following circumstances:
    ///
    /// 1. A message is edited
    /// 2. A message is deleted
    /// 3. A message is pinned/unpinned
    /// 4. A reaction is added/removed to a message
    pub async fn process_message_updates(&self) -> Result<()> {
        let mut listener = listen_for!(
            self,
            Event::MessageDeleted { .. }
            | Event::MessageEdited { .. }
            | Event::MessagePinStatusUpdated { .. }
            | Event::MessageReactionUpdate { .. }
        );

        let store = &self.base.objects.messages;

        while let Some(event) = listener.recv().await {
            match &*event {
                &Event::MessageDeleted { conversation_id, message_id } => {
                    store.objects.remove(&message_id);
                    store.secrets.remove(&message_id);

                    let pins = &self.base.objects.conversations.pinned;

                    pins.entry(conversation_id)
                        .or_default()
                        .remove(&message_id);
                },
                Event::MessageEdited { message_id, new_body, .. } => {
                    if let Some(message) = store.objects.get_mut(message_id).as_deref_mut() {
                        message.body = new_body.clone(); // shouldn't be a performance issue, i'm optimistic
                    }
                },
                &Event::MessagePinStatusUpdated { message_id, conversation_id, pinned } => {
                    let pins = &self.base.objects.conversations.pinned;

                    if let Some(set) = pins.get_mut(&conversation_id) {
                        if pinned {
                            set.insert(message_id);
                        }
                        else {
                            set.remove(&message_id);
                        }
                    }

                    if let Some(message) = store.objects.get_mut(&message_id).as_deref_mut() {
                        message.pinned = pinned;
                    }
                },
                &Event::MessageReactionUpdate { message_id, reaction, exists } => {
                    let mut guard = store.objects.get_mut(&message_id);

                    let Some(message) = guard.as_deref_mut() else {
                        continue;
                    };

                    if exists {
                        message.reactions.push(reaction)
                    }
                    else {
                        message.reactions.retain(|r| *r != reaction);
                    }
                },
                _ => continue
            };
        }

        Ok(())
    }

    /// Process updates to groups like session updates when membership changes.
    pub async fn process_group_updates(&self) -> Result<()> {
        let mut listener = listen_for!(
            self,
            Event::MemberJoinedGroup { .. }
            | Event::MemberLeftGroup { .. }
            | Event::GroupAppearanceUpdated { .. }
            | Event::GroupInviteRotated { .. }
            | Event::GroupLockStatusUpdated { .. }
            | Event::NewGroupEmoji(_)
            | Event::GroupEmojiDeleted(_)
            | Event::ConversationTimerUpdated { .. }
        );

        let user_id = self.base.user_id;

        let store = &self.base.objects;

        let groups = &store.groups.objects;

        let group_emojis = &store.groups.emojis;
        let all_emojis = &store.emojis;

        while let Some(event) = listener.recv().await {
            match &*event {
                &Event::MemberJoinedGroup { group_id, member_id } => {
                    if user_id == member_id {
                        continue;
                    }

                    if let Some(mut group) = groups.get_mut(&group_id) {
                        group.members.push(GroupMember {
                            user_id: member_id,
                            joined_at: Utc::now(),
                            read_watermark: None
                        });
                    }
                    else if let Ok(Some(group)) = self.fetch_group(group_id).await {
                        groups.insert(group.id, group);
                    }

                    store.conversations.sessions.remove(&group_id);
                },
                &Event::MemberLeftGroup { group_id, member_id } => {
                    if let Some(mut group) = groups.get_mut(&group_id) {
                        group.members.retain(|m| m.user_id != member_id);
                    }

                    store.conversations.sessions.remove(&group_id);
                },
                Event::GroupAppearanceUpdated { group_id, new_name, new_avatar } => {
                    if let Some(mut group) = groups.get_mut(group_id) {
                        if let Some(name) = new_name {
                            group.name = name.to_string();
                        }

                        group.avatar = *new_avatar;
                    }
                },
                &Event::GroupInviteRotated { group_id, new_invite } => {
                    if let Some(mut group) = groups.get_mut(&group_id) {
                        group.invite_code = new_invite;
                    }
                }
                &Event::GroupLockStatusUpdated { group_id, locked } => {
                    if let Some(mut group) = groups.get_mut(&group_id) {
                        group.locked = locked;
                    }
                }
                Event::NewGroupEmoji(emoji) => {
                    group_emojis
                        .entry(emoji.group_id)
                        .or_default()
                        .insert(emoji.id);

                    all_emojis.insert(emoji.id, emoji.clone());
                }
                Event::GroupEmojiDeleted(emoji_id) => {
                    if let Some((_, emoji)) = all_emojis.remove(emoji_id) {
                        group_emojis
                            .get(&emoji.group_id)
                            .and_then(|set| set.remove(emoji_id));
                    }
                },
                &Event::ConversationTimerUpdated { conversation_id, new_message_timer } => {
                    self.base.objects.conversations.default_message_timers.insert(conversation_id, new_message_timer);
                }
                _ => continue
            };
        }

        Ok(())
    }
}

// Method for fetching blobs from the server.
impl Client {
    /// Fetch an asset's raw bytes from the server, returning `None` if it doesn't exist.
    pub async fn fetch_asset(&self, asset_id: AssetID) -> Result<Option<Vec<u8>>> {
        self.base.conn.access_route("assets.get", async |stream| {
            stream.send(&asset_id).await?;

            let maybe_asset = stream.receive::<RouteResult<_>>().await??;

            Ok(maybe_asset)
        }).await
    }

    /// Fetch and decrypt a message attachment, returning `None` if it doesn't exist
    /// and an error on failure to decrypt.
    pub async fn fetch_attachment(&self, asset_id: AssetID, message_secret: Secret) -> Result<Option<Vec<u8>>> {
        let Some(bytes) = self.fetch_asset(asset_id).await? else {
            return Ok(None);
        };

        let enc: Encrypted<Vec<u8>> = bitcode::deserialize(&bytes)?;

        let decrypted = message_secret.decrypt(&enc)?;

        Ok(Some(decrypted))
    }
}

#[derive(Clone)]
pub struct MessageHistory {
    conn: ServerConnection,
    conversation_id: SnowflakeID,
    before: Option<DateTime<Utc>>,
    after: Option<DateTime<Utc>>,
    limit: u8
}

impl MessageHistory {
    pub fn new(
        conn: ServerConnection,
        conversation_id: SnowflakeID,
        before: Option<DateTime<Utc>>,
        after: Option<DateTime<Utc>>,
        limit: u8
    ) -> Self {
        Self {
            conn,
            conversation_id,
            before,
            after,
            limit: limit.min(100)
        }
    }

    /// Fetch the next batch of messages.
    pub async fn fetch_next(&mut self) -> Result<Vec<(Message, Secret)>> {
        let params = match (self.before, self.after) {
            (Some(before), Some(after)) => MessageHistoryParams::Between(before, after),
            (Some(before), None) => MessageHistoryParams::Before(before),
            (None, Some(after)) => MessageHistoryParams::After(after),
            (None, None) => MessageHistoryParams::Latest
        };

        let messages = self.conn.access_route("messages.history.get", async |stream| {
            stream.send(&GetMessageHistoryData {
                conversation_id: self.conversation_id,
                params,
                limit: self.limit
            }).await?;

            let messages: Vec<(Message, Secret)> = stream.receive::<RouteResult<_>>().await??;

            Ok(messages)
        }).await?;

        if matches!(params, MessageHistoryParams::Between(_, _))
            && let Some((last_msg, _)) = messages.last()
        {
            // Tighten bounds for next fetch
            self.before = Some(last_msg.sent_at);
        }

        Ok(messages)
    }
}

/// Methods for interacting with messages.
impl Client {
    /// Fetch a message from the server, returning `None` if it doesn't exist.
    ///
    /// This will clone it out of the cache if found.
    pub async fn fetch_message(&self, message_id: SnowflakeID) -> Result<Option<(Message, Secret)>> {
        let maybe_message = self.base.objects.messages.objects.get(&message_id);
        let maybe_secret = self.base.objects.messages.secrets.get(&message_id);

        if let (Some(message), Some(secret)) = (maybe_message, maybe_secret) {
            return Ok(Some((message.clone(), *secret)));
        }

        let result: RouteResult<(Message, Encrypted<Secret>)> = self.base.conn.access_route("messages.get", async |stream| {
            stream.send(&message_id).await?;

            let r = stream.receive().await?;

            Ok(r)
        }).await?;

        match result {
            Ok((msg, secret)) => {
                let encryption_secret = self.base.master_secret.encryption_secret();

                let message_secret = encryption_secret.decrypt(&secret)?;

                self.base.objects.messages.objects.insert(msg.id, msg.clone());
                self.base.objects.messages.secrets.insert(msg.id, message_secret);

                Ok(Some((msg, message_secret)))
            },
            Err(RouteError::Messages(MessagesRouteError::MessageNotFound)) => Ok(None),
            Err(e) => bail!(e)
        }
    }

    /// Retrieves a session for a conversation. If the session doesn't exist locally,
    /// it gets fetched from the server and added back to local storage.
    async fn get_or_fetch_session(&self, conversation_id: SnowflakeID) -> Result<GroupSession> {
        let encryption_secret = self.base.master_secret.encryption_secret();
        let box_secret = self.base.master_secret.box_secret();

        let sessions = &self.base.objects.conversations.sessions;

        if let Some(session) = sessions.get(&conversation_id) {
            return Ok(session.pickle().into());
        }

        let maybe_session = self.base.conn.access_route("messages.sessions.ensure", async |stream| {
            stream.send(&conversation_id).await?;

            let needs_new_session: bool = stream.receive::<RouteResult<_>>().await??;

            if !needs_new_session {
                return Ok(None);
            }

            let session = GroupSession::new(SessionConfig::version_1());

            let members: HashMap<SnowflakeID, BoxPublicKey> = stream.receive::<RouteResult<_>>().await??;

            let session_keys = members
                .into_iter()
                .map(|(id, bpk)| (id, box_secret.box_for(&session.session_key(), bpk)))
                .collect();

            let encrypted_session = EncryptedChatSession {
                outbound: encryption_secret.encrypt(&session.pickle()),
                inbounds: session_keys
            };

            stream.send(&encrypted_session).await?;

            stream.receive::<RouteResult<()>>().await??;

            Ok(Some(session))
        }).await?;

        let session = match maybe_session {
            Some(session) => session,
            None => {
                self.base.conn.access_route("messages.sessions.get", async |stream| {
                    stream.send(&conversation_id).await?;

                    let encrypted: Encrypted<GroupSessionPickle> = stream.receive::<RouteResult<_>>().await??;

                    let pickle = encryption_secret.decrypt(&encrypted)?;

                    Ok(pickle.into())
                }).await?
            }
        };

        sessions.insert(conversation_id, session.pickle().into());

        Ok(session)
    }

    async fn send_new_message(
        &self,
        conversation_id: SnowflakeID,
        content: &str,
        files: Vec<File>,
        delete_after: Option<TimeDelta>,
        replied_to: Option<SnowflakeID>
    ) -> Result<Message> {
        let encryption_secret = self.base.master_secret.encryption_secret();
        let message_secret = Secret::random();

        let mut session = self.get_or_fetch_session(conversation_id).await?;

        let message = self.base.conn.access_route("messages.send", async |stream| {
            stream.send(&SendMessageData {
                conversation_id,
                replied_to,
                message_body: message_secret.encrypt(&content).cast(),
                key_for_author: encryption_secret.encrypt(&message_secret),
                key_for_others: session.encrypt(message_secret),
                delete_after
            }).await?;

            stream.receive::<RouteResult<()>>().await??;

            let attachments: Vec<_> = files
                .iter()
                .map(|file| UploadedAttachment {
                    filename: file.name().to_string(),
                    data: message_secret.encrypt(&file.content()).cast()
                })
                .collect();

            stream.send(&attachments).await?;

            let message: Message = stream.receive::<RouteResult<_>>().await??;

            Ok(message)
        }).await?;

        self.base
            .objects
            .conversations
            .messages
            .entry(conversation_id)
            .or_default()
            .insert(message.id);

        let store = &self.base.objects.messages;

        store.secrets.insert(message.id, message_secret);
        store.objects.insert(message.id, message.clone());

        Ok(message)
    }

    /// Send a message into a conversation.
    pub async fn send_message(
        &self,
        conversation_id: SnowflakeID,
        content: &str,
        files: Vec<File>,
        delete_after: Option<TimeDelta>
    ) -> Result<Message> {
        self.send_new_message(
            conversation_id,
            content,
            files,
            delete_after,
            None
        ).await
    }

    /// Reply to a message with a new message
    pub async fn reply_to_message(
        &self,
        conversation_id: SnowflakeID,
        replying_to: SnowflakeID,
        content: &str,
        files: Vec<File>,
        delete_after: Option<TimeDelta>
    ) -> Result<Message> {
        self.send_new_message(
            conversation_id,
            content,
            files,
            delete_after,
            Some(replying_to)
        ).await
    }

    /// Edit a message's content.
    pub async fn edit_message(&self, message_id: SnowflakeID, new_content: &str) -> Result<()> {
        let secrets = &self.base.objects.messages.secrets;

        let message_secret = secrets
            .get(&message_id)
            .as_deref()
            .copied()
            .context("message secret not found in local cache, fetch it first?")?;

        self.base.conn.access_route("messages.edit", async |stream| {
            stream.send(&EditMessageData {
                message_id,
                new_body: message_secret.encrypt(&new_content).cast()
            }).await?;

            stream.receive::<RouteResult<()>>().await??;

            Ok(())
        }).await?;

        Ok(())
    }

    /// Add a reaction to this message, returning the created reaction.
    pub async fn add_reaction_to_message(&self, message_id: SnowflakeID, emoji_id: SnowflakeID) -> Result<Reaction> {
        let reaction = Reaction {
            author: self.base.user_id,
            emoji: emoji_id
        };

        let message_store = &self.base.objects.messages.objects;

        if let Some(message) = message_store.get(&message_id)
            && message.reactions.contains(&reaction)
        {
            return Ok(reaction);
        }

        self.base.conn.access_route("messages.reactions.add", async |stream| {
            stream.send(&AddNewReactionData {
                emoji_id,
                message_id
            }).await?;

            stream.receive::<RouteResult<()>>().await??;

            Ok(())
        }).await?;

        if let Some(mut message) = message_store.get_mut(&message_id) {
            message.reactions.push(reaction);
        }

        Ok(reaction)
    }

    /// Remove a reaction to this message.
    pub async fn remove_reaction_to_message(&self, message_id: SnowflakeID, emoji_id: SnowflakeID) -> Result<()> {
        let reaction = Reaction {
            author: self.base.user_id,
            emoji: emoji_id
        };

        let message_store = &self.base.objects.messages.objects;

        let reaction_index = message_store
            .get(&message_id)
            .and_then(|msg| msg.reactions.iter().position(|r| *r == reaction));

        if reaction_index.is_none() {
            return Ok(());
        }

        self.base.conn.access_route("messages.reactions.remove", async |stream| {
            stream.send(&RemoveReactionData { emoji_id, message_id }).await?;

            stream.receive::<RouteResult<()>>().await??;

            Ok(())
        }).await?;

        if let Some(mut message) = message_store.get_mut(&message_id) {
            message.reactions.remove(reaction_index.unwrap());
        }

        Ok(())
    }

    /// Pin or unpin a message.
    async fn change_pin_status(&self, message_id: SnowflakeID, new_pin_status: bool) -> Result<()> {
        if let Some(message) = self.base.objects.messages.objects.get(&message_id)
            && message.pinned == new_pin_status
        {
            return Ok(());
        }

        self.base.conn.access_route("messages.pinned.update", async |stream| {
            stream.send(&UpdateMessagePinData {
                message_id,
                new_pin_status
            }).await?;

            stream.receive::<RouteResult<()>>().await??;

            Ok(())
        }).await
    }

    /// Pin a message in a conversation.
    pub async fn pin_message(&self, message_id: SnowflakeID) -> Result<()> {
        self.change_pin_status(message_id, true).await
    }

    /// Unpin a message in a conversation.
    pub async fn unpin_message(&self, message_id: SnowflakeID) -> Result<()> {
        self.change_pin_status(message_id, false).await
    }

    /// Return an iterator over message history for a conversation.
    pub async fn get_conversation_history(
        &self,
        conversation_id: SnowflakeID,
        before: Option<DateTime<Utc>>,
        after: Option<DateTime<Utc>>,
        limit: u8
    ) -> MessageHistory {
        MessageHistory::new(
            self.base.conn.clone(),
            conversation_id,
            before,
            after,
            limit
        )
    }

    /// Mark a message as read in a conversation.
    pub async fn mark_message_as_read(&self, message_id: SnowflakeID, conversation_id: SnowflakeID) -> Result<()> {
        let read_watermarks = &self.base.objects.conversations.read_watermarks;

        let user_id = self.base.user_id;

        let self_watermark = read_watermarks
            .get(&conversation_id)
            .and_then(|watermarks| watermarks.get(&user_id).as_deref().cloned());

        if let Some(watermark) = self_watermark && watermark.message_id >= message_id {
            return Ok(());
        }

        self.base.conn.access_route("messages.watermark.update", async |stream| {
            stream.send(&UpdateReadWatermarkData {
                conversation_id,
                message_id
            }).await?;

            stream.receive::<RouteResult<()>>().await??;

            Ok(())
        }).await?;

        read_watermarks
            .entry(conversation_id)
            .or_default()
            .insert(user_id, ReadWatermark {
                message_id,
                read_at: Utc::now()
            });

        Ok(())
    }

    /// Fetch all the pinned messages in the chat as one massive batch,
    /// with no substitution from local storage. The pins here are added
    /// to local storage.
    pub async fn get_all_pinned_messages(&self, conversation_id: SnowflakeID) -> Result<Vec<SnowflakeID>> {
        let pinned_messages = self.base.conn.access_route("messages.pinned.get", async |stream| {
            stream.send(&conversation_id).await?;

            let ids: Compressed<Vec<SnowflakeID>> = stream.receive::<RouteResult<_>>().await??;

            Ok(ids.decompress())
        }).await?;

        let pinned = &self.base.objects.conversations.pinned;

        if let Some(mut set) = pinned.get_mut(&conversation_id) {
            set.extend(pinned_messages.iter().copied());
        }

        Ok(pinned_messages)
    }
}

// Methods for interacting with groups as any member.
impl Client {
    /// Fetch a group from the server, returning `None` if it doesn't exist,
    /// and cloning it out of cache if found there.
    pub async fn fetch_group(&self, group_id: SnowflakeID) -> Result<Option<Group>> {
        if let Some(group) = self.base.objects.groups.objects.get(&group_id) {
            return Ok(Some(group.clone()));
        }

        let group = self.base.conn.access_route("groups.get", async |stream| {
            stream.send(&group_id).await?;

            let r: RouteResult<Group> = stream.receive().await?;

            match r {
                Ok(g) => {
                    self.base.objects.groups.objects.insert(g.id, g.clone());

                    Ok(Some(g))
                },
                Err(RouteError::Group(GroupRouteError::GroupNotFound)) => Ok(None),
                Err(e) => bail!(e)
            }
        }).await?;

        Ok(group)
    }

    /// Create a new group.
    pub async fn create_group(
        &self,
        name: Option<&str>,
        initial_members: Vec<SnowflakeID>
    ) -> Result<Group> {
        let group: Group = self.base.conn.access_route("groups.create", async |stream| {
            stream.send(&CreateNewGroupData {
                name: name.map(String::from),
                initial_members
            }).await?;

            let group = stream.receive::<RouteResult<_>>().await??;

            Ok(group)
        }).await?;

        self.base.objects.groups.objects.insert(group.id, group.clone());

        Ok(group)
    }

    /// Join a group using an invite code.
    pub async fn join_group(&self, invite: GroupInvite) -> Result<Group> {
        let group = self.base.conn.access_route("groups.join", async |stream| {
            stream.send(&invite).await?;

            let group: Group = stream.receive::<RouteResult<_>>().await??;

            Ok(group)
        }).await?;

        self.base.objects.groups.objects.insert(group.id, group.clone());

        Ok(group)
    }

    /// Leave a group.
    pub async fn leave_group(&self, group_id: SnowflakeID) -> Result<()> {
        self.base.conn.access_route("groups.leave", async |stream| {
            stream.send(&group_id).await?;

            stream.receive::<RouteResult<()>>().await??;

            Ok(())
        }).await?;

        self.base.objects.groups.objects.remove(&group_id);

        let conversations = &self.base.objects.conversations;

        conversations.sessions.remove(&group_id);
        conversations.pinned.remove(&group_id);
        conversations.read_watermarks.remove(&group_id);

        if let Some((_, message_ids)) = conversations.messages.remove(&group_id) {
            let messages = &self.base.objects.messages;

            messages.objects.retain(|id, _| !message_ids.contains(id));
            messages.secrets.retain(|id, _| !message_ids.contains(id));
        }

        Ok(())
    }

    /// Add a friend to a group.
    pub async fn add_friend_to_group(&self, group_id: SnowflakeID, friend_id: SnowflakeID) -> Result<()> {
        self.base.conn.access_route("groups.add", async |stream| {
            stream.send(&AddFriendToGroupData {
                group_id,
                friend_id
            }).await?;

            stream.receive::<RouteResult<()>>().await??;

            Ok(())
        }).await?;

        Ok(())
    }
}

/// Methods for interacting with groups as the owner.
impl Client {
    async fn change_group_lock(&self, group_id: SnowflakeID, new_lock_status: bool) -> Result<()> {
        self.base.conn.access_route("groups.lock.update", async |stream| {
            stream.send(&UpdateGroupLockData {
                group_id,
                new_lock_status
            }).await?;

            stream.receive::<RouteResult<()>>().await??;

            Ok(())
        }).await
    }

    /// Lock a group.
    pub async fn lock_group(&self, group_id: SnowflakeID) -> Result<()> {
        self.change_group_lock(group_id, true).await
    }

    /// Unlock a group.
    pub async fn unlock_group(&self, group_id: SnowflakeID) -> Result<()> {
        self.change_group_lock(group_id, false).await
    }

    /// Rotate the invite code of a group.
    pub async fn rotate_invite_code(&self, group_id: SnowflakeID) -> Result<GroupInvite> {
        self.base.conn.access_route("groups.invites.rotate", async |stream| {
            stream.send(&group_id).await?;

            let invite = stream.receive::<RouteResult<_>>().await??;

            Ok(invite)
        }).await
    }

    /// Kick a member from a group.
    pub async fn kick_member_from_group(&self, group_id: SnowflakeID, member_id: SnowflakeID) -> Result<()> {
        self.base.conn.access_route("groups.members.kick", async |stream| {
            stream.send(&KickMemberData {
                group_id,
                member_id
            }).await?;

            stream.receive::<RouteResult<()>>().await??;

            Ok(())
        }).await
    }

    /// Ban a member from a group.
    pub async fn ban_member_from_group(
        &self,
        group_id: SnowflakeID,
        member_id: SnowflakeID,
        reason: Option<&str>
    ) -> Result<()> {
        self.base.conn.access_route("groups.members.ban", async |stream| {
            stream.send(&BanMemberData {
                group_id,
                member_id,
                reason: reason.map(String::from)
            }).await?;

            stream.receive::<RouteResult<()>>().await??;

            Ok(())
        }).await
    }

    // Get the ban list of a group.
    pub async fn get_ban_list(&self, group_id: SnowflakeID) -> Result<Vec<BannedMember>> {
        self.base.conn.access_route("groups.members.banned.get", async |stream| {
            stream.send(&group_id).await?;

            let list = stream.receive::<RouteResult<_>>().await??;

            Ok(list)
        }).await
    }

    /// Unban a banned user from a group.
    pub async fn unban_user_from_group(&self, group_id: SnowflakeID, user_id: SnowflakeID) -> Result<()> {
        self.base.conn.access_route("groups.members.unban", async |stream| {
            stream.send(&UnbanMemberData {
                group_id,
                member_id: user_id
            }).await?;

            stream.receive::<RouteResult<()>>().await??;

            Ok(())
        }).await
    }

    /// Update the name of a group.
    pub async fn update_group_name(&self, group_id: SnowflakeID, new_name: &str) -> Result<()> {
        self.base.conn.access_route("groups.appearance.update", async |stream| {
            stream.send(&UpdateGroupAppearanceData {
                group_id,
                new_name: Some(new_name.to_string()),
                new_avatar: None
            }).await?;

            stream.receive::<RouteResult<()>>().await??;

            Ok(())
        }).await
    }

    /// Update the avatar of a group.
    pub async fn update_group_avatar(&self, group_id: SnowflakeID, new_avatar: Vec<u8>) -> Result<()> {
        self.base.conn.access_route("groups.appearance.update", async |stream| {
            stream.send(&UpdateGroupAppearanceData {
                group_id,
                new_name: None,
                new_avatar: Some(new_avatar)
            }).await?;

            stream.receive::<RouteResult<()>>().await??;

            Ok(())
        }).await
    }

    /// Get the list of emoji IDs for a group, adding them to local storage.
    pub async fn get_group_emoji_ids(&self, group_id: SnowflakeID) -> Result<Vec<SnowflakeID>> {
        let group_emojis = &self.base.objects.groups.emojis;

        self.base.conn.access_route("groups.emojis.all.get", async |stream| {
            stream.send(&group_id).await?;

            let emoji_ids: Vec<SnowflakeID> = stream.receive::<RouteResult<Compressed<_>>>().await??.decompress();

            if let Some(mut store) = group_emojis.get_mut(&group_id) {
                store.extend(emoji_ids.iter().copied());
            }

            Ok(emoji_ids)
        }).await
    }

    /// Create a new emoji for a group.
    pub async fn create_new_group_emoji(
        &self,
        group_id: SnowflakeID,
        name: &str,
        bytes: Vec<u8>
    ) -> Result<Emoji> {
        self.base.conn.access_route("groups.emojis.create", async |stream| {
            stream.send(&CreateNewEmojiData {
                group_id,
                name: name.to_string()
            }).await?;

            stream.receive::<RouteResult<()>>().await??;

            stream.send(&bytes).await?;

            let emoji = stream.receive::<RouteResult<_>>().await??;

            Ok(emoji)
        }).await
    }

    /// Delete an emoji in a group.
    pub async fn delete_group_emoji(&self, group_id: SnowflakeID, emoji_id: SnowflakeID) -> Result<()> {
        self.base.conn.access_route("groups.emojis.create", async |stream| {
            stream.send(&DeleteGroupEmojiData {
                group_id,
                emoji_id
            }).await?;

            stream.receive::<RouteResult<()>>().await??;

            Ok(())
        }).await
    }

    /// Fetch an emoji, cloning it out of cache if found there,
    /// and returning [`None`] if not found anywhere.
    pub async fn fetch_emoji(&self, emoji_id: SnowflakeID) -> Result<Option<Emoji>> {
        let all_emojis = &self.base.objects.emojis;
        let group_emojis = &self.base.objects.groups.emojis;

        if let Some(emoji) = all_emojis.get(&emoji_id) {
            return Ok(Some(emoji.clone()));
        }

        let result = self.base.conn.access_route("groups.emojis.get", async |stream| {
            stream.send(&emoji_id).await?;

            let r: RouteResult<Emoji> = stream.receive().await?;

            match r {
                Ok(emoji) => {
                    group_emojis
                        .entry(emoji.group_id)
                        .or_default()
                        .insert(emoji.id);

                    all_emojis.insert(emoji.id, emoji.clone());

                    Ok(Some(emoji))
                },
                Err(RouteError::Group(GroupRouteError::EmojiNotFound)) => Ok(None),
                Err(e) => bail!(e)
            }
        }).await?;

        Ok(result)
    }
}

/// Methods for interacting with conversations.
impl Client {
    /// Notify the server this user is typing in a given conversation.
    ///
    /// This will only send one request, not continuously notify the server.
    pub async fn send_typing_event(&self, conversation_id: SnowflakeID) -> Result<()> {
        self.base.conn.access_route("conversations.typing.start", async |stream| {
            stream.send(&conversation_id).await?;

            stream.receive::<RouteResult<()>>().await??;

            Ok(())
        }).await
    }

    /// Subscribe to typing events for a given conversation.
    pub async fn subscribe_to_typing_events(&self, conversation_id: SnowflakeID) -> Result<()> {
        self.base.conn.access_route("conversations.typing.subscribe", async |stream| {
            stream.send(&conversation_id).await?;

            stream.receive::<RouteResult<()>>().await??;

            Ok(())
        }).await
    }

    /// Unsubscribe from all typing events.
    pub async fn unsubscribe_from_typing_events(&self) -> Result<()> {
        self.base.conn.access_route("conversations.typing.unsubscribe", async |stream| {
            stream.receive::<RouteResult<()>>().await??;

            Ok(())
        }).await
    }

    /// Get the default message timer for a conversation, cloning it out of cache if found there.
    pub async fn fetch_conversation_timer(&self, conversation_id: SnowflakeID) -> Result<Option<TimeDelta>> {
        let default_timers = &self.base.objects.conversations.default_message_timers;

        if let Some(timer) = default_timers.get(&conversation_id) {
            return Ok(*timer);
        }

        self.base.conn.access_route("conversations.timers.default.get", async |stream| {
            stream.send(&conversation_id).await?;

            let timer = stream.receive::<RouteResult<_>>().await??;

            default_timers.insert(conversation_id, timer);

            Ok(timer)
        }).await
    }

    /// Update the default message timer for a conversation.
    pub async fn update_conversation_timer(
        &self,
        conversation_id: SnowflakeID,
        new_message_timer: Option<TimeDelta>
    ) -> Result<Option<TimeDelta>> {
        self.base.conn.access_route("conversations.timers.default.get", async |stream| {
            stream.send(&UpdateDefaultMessageTimerData {
                conversation_id,
                new_message_timer
            }).await?;

            let timer = stream.receive::<RouteResult<_>>().await??;

            self.base.objects.conversations.default_message_timers.insert(conversation_id, new_message_timer);

            Ok(timer)
        }).await
    }

    /// Get the IDs of groups the user is a member of.
    pub async fn get_user_group_ids(&self) -> Result<Vec<SnowflakeID>> {
        self.base.conn.access_route("users.groups.get", async |stream| {
            let group_ids = stream.receive::<RouteResult<Compressed<_>>>().await??;

            Ok(group_ids.decompress())
        }).await
    }
}

/// An interactive user search.
pub struct UserSearch {
    stream: Stream,
    current_text: String,
    results: Vec<UserSearchResult>,
    end_of_search: bool
}

impl UserSearch {
    /// Get the current text being searched for.
    pub fn current_text(&self) -> &str {
        &self.current_text
    }

    /// Get the current results.
    pub fn current_results(&self) -> &[UserSearchResult] {
        &self.results
    }

    /// Edit the search query on the server-side.
    pub async fn edit_query(&mut self, new_query: &str) -> Result<&[UserSearchResult]> {
        self.results.clear();
        self.end_of_search = false;

        let action = UserSearchAction::ChangeQuery(new_query.to_string());

        self.stream.send(&action).await?;

        self.results = self.stream.receive::<RouteResult<_>>().await??;

        Ok(&self.results)
    }

    /// Fetch the next set of results.
    pub async fn fetch_more_results(&mut self) -> Result<&[UserSearchResult]> {
        if self.end_of_search {
            return Ok(&[]);
        }

        self.stream.send(&UserSearchAction::NextPage).await?;

        let results: Vec<_> = self.stream.receive::<RouteResult<_>>().await??;

        if results.is_empty() {
            self.end_of_search = true;
        }

        let len = self.results.len();

        self.results.extend(results);

        Ok(&self.results[len..])
    }

    /// Quit searching, closing the stream and abandoning all results.
    pub async fn quit_searching(mut self) -> Result<Vec<UserSearchResult>> {
        self.stream.send(&UserSearchAction::Quit).await?;

        self.stream.receive::<RouteResult<()>>().await??;

        Ok(self.results)
    }
}

/// Methods for interacting with users.
impl Client {
    /// Fetch a user account, cloning it out of cache if found there.
    pub async fn fetch_user(&self, user_id: SnowflakeID) -> Result<Option<User>> {
        if let Some(user) = self.base.objects.users.get(&user_id) {
            return Ok(Some(user.clone()));
        }

        self.base.conn.access_route("users.get", async |stream| {
            stream.send(&user_id).await?;

            let r: RouteResult<User> = stream.receive().await?;

            match r {
                Ok(user) => {
                    self.base.objects.users.insert(user.id, user.clone());

                    Ok(Some(user))
                },
                Err(RouteError::User(UserRouteError::NotFound)) => Ok(None),
                Err(e) => bail!(e)
            }
        }).await
    }

    /// Change the account password.
    pub async fn change_password(&self, new_password: &str) -> Result<()> {
        let raw_secret: Secret = self.base.master_secret.into();

        let new_secret = PasswordProtected::new(&raw_secret, new_password);

        self.base.conn.access_route("users.password.change", async |stream| {
            stream.send(&new_secret).await?;

            stream.receive::<RouteResult<()>>().await??;

            Ok(())
        }).await
    }

    /// Delete this account. If `delete_all_data` is `true`, this will delete all messages
    /// and conversations with other people. Otherwise, the account is just edited to appear
    /// deleted and gets locked permanently.
    pub async fn delete_account(self, delete_all_data: bool) -> Result<()> {
        self.base.conn.access_route("users.delete", async |stream| {
            stream.send(&delete_all_data).await?;

            stream.receive::<RouteResult<()>>().await??;

            Ok(())
        }).await
    }

    /// Update the user account.
    pub async fn update_user_account(&self, update_fn: impl FnOnce(&mut User)) -> Result<()> {
        let original = self.user().await;

        let mut changed = original.clone();

        update_fn(&mut changed);

        let diffs = original.diff(&changed);

        if diffs.is_empty() {
            return Ok(());
        }

        self.base.conn.access_route("users.update", async |stream| {
            stream.send(&diffs).await?;

            stream.receive::<RouteResult<()>>().await??;

            Ok(())
        }).await?;

        let mut user = self.base.user.lock().await;

        *user = changed;

        Ok(())
    }

    /// Subscribe to profile updates for the following users.
    pub async fn subscribe_to_profile_updates_for(&self, users: Vec<SnowflakeID>) -> Result<()> {
        self.base.conn.access_route("users.updates.subscribe", async |stream| {
            stream.send(&users).await?;

            stream.receive::<RouteResult<()>>().await??;

            Ok(())
        }).await
    }

    /// Unsubscribe from profile updates for the following users.
    pub async fn unsubscribe_from_profile_updates_about(&self, users: Vec<SnowflakeID>) -> Result<()> {
        self.base.conn.access_route("users.updates.unsubscribe", async |stream| {
            stream.send(&users).await?;

            stream.receive::<RouteResult<()>>().await??;

            Ok(())
        }).await
    }

    /// Unsubscribe from profile updates about any users.
    pub async fn unsubscribe_from_all_profile_updates(&self) -> Result<()> {
        self.base.conn.access_route("users.updates.unsubscribe.all", async |stream| {
            stream.receive::<RouteResult<()>>().await??;

            Ok(())
        }).await
    }

    /// Search for new users, providing an interactive view.
    pub async fn search_new_users(&self) -> Result<UserSearch> {
        let stream = self.base.conn.access_route_manually("route").await?;

        Ok(UserSearch {
            stream,
            current_text: String::new(),
            results: vec![],
            end_of_search: false
        })
    }
}

/// Methods for interacting with friends.
impl Client {
    /// Get a list of pending friend requests.
    pub async fn get_pending_friend_requests(&self) -> Result<FriendRequests> {
        self.base.conn.access_route("users.friends.requests.get", async |stream| {
            let requests = stream.receive::<RouteResult<_>>().await??;

            Ok(requests)
        }).await
    }

    /// Send a friend request to another user.
    pub async fn send_friend_request_to(&self, recipient: SnowflakeID) -> Result<()> {
        self.base.conn.access_route("users.friends.requests.create", async |stream| {
            stream.send(&recipient).await?;

            stream.receive::<RouteResult<OutgoingFriendRequest>>().await??;

            Ok(())
        }).await
    }

    /// Accept a friend request from another user.
    pub async fn accept_friend_request_from(&self, sender: SnowflakeID) -> Result<()> {
        self.base.conn.access_route("users.friends.requests.accept", async |stream| {
            stream.send(&sender).await?;

            let conversation_id: SnowflakeID = stream.receive::<RouteResult<_>>().await??;

            let friend = Friend {
                user_id: sender,
                friends_since: Utc::now(),
                conversation_id,
                read_watermarks: ReadWatermarks {
                    ours: None,
                    theirs: None
                }
            };

            self.base.objects.friends.insert(sender, friend);

            Ok(())
        }).await
    }

    /// Decline a friend request from another user.
    pub async fn decline_friend_request_from(&self, sender: SnowflakeID) -> Result<()> {
        self.base.conn.access_route("users.friends.requests.decline", async |stream| {
            stream.send(&sender).await?;

            stream.receive::<RouteResult<()>>().await??;

            Ok(())
        }).await
    }

    /// Cancel a friend request sent to another user.
    pub async fn cancel_friend_request_to(&self, receiver: SnowflakeID) -> Result<()> {
        self.base.conn.access_route("users.friends.requests.cancel", async |stream| {
            stream.send(&receiver).await?;

            stream.receive::<RouteResult<()>>().await??;

            Ok(())
        }).await
    }

    /// Get a list of the user's friends, cloning them out of local cache,
    /// or fetching if the local cache is empty.
    pub async fn get_friends(&self) -> Result<Vec<Friend>> {
        let friends_store = &self.base.objects.friends;

        let mut friends: Vec<Friend> = friends_store.iter().map(|r| *r).collect();

        if friends.is_empty() {
            self.base.conn.access_route("users.friends.get", async |stream| {
                friends = stream.receive::<RouteResult<_>>().await??;

                Ok(())
            }).await?;

            for f in friends.iter().copied() {
                friends_store.insert(f.user_id, f);
            }
        }

        Ok(friends)
    }

    /// Try to get a [`Friend`] with the given user ID from local cache.
    pub fn get_friend_from_user_id(&self, user_id: SnowflakeID) -> Option<Friend> {
        self.base.objects.friends.get(&user_id).as_deref().copied()
    }

    /// Remove another user as a friend.
    ///
    /// This will delete the conversation history.
    pub async fn remove_friend(&self, user_id: SnowflakeID) -> Result<()> {
        self.base.conn.access_route("users.friends.remove", async |stream| {
            stream.send(&user_id).await?;

            stream.receive::<RouteResult<()>>().await??;

            Ok(())
        }).await?;

        let objects = &self.base.objects;

        if let Some((_, friend)) = objects.friends.remove(&user_id) {
            objects.conversations.default_message_timers.remove(&friend.conversation_id);
            objects.conversations.pinned.remove(&friend.conversation_id);
            objects.conversations.read_watermarks.remove(&friend.conversation_id);
            objects.conversations.sessions.remove(&friend.conversation_id);

            if let Some((_, messages)) = objects.conversations.messages.remove(&friend.conversation_id) {
                for message_id in messages {
                    objects.messages.objects.remove(&message_id);
                }
            }
        }

        Ok(())
    }
}
