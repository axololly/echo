 -- TODO: add length checks to BYTEA columns

 CREATE TYPE "Activity" AS ENUM(
    'Online',
    'Idle',
    'DoNotDisturb',
    'Offline'
);

CREATE DOMAIN "AssetID" AS TEXT CHECK (length(VALUE) = 64);

-- The main table containing all the user information.
-- One row here is an entire user account.
CREATE TABLE users (
    id INT8 PRIMARY KEY,
    name TEXT NOT NULL UNIQUE
        CHECK (char_length(name) BETWEEN 3 AND 20),
    display_name TEXT NOT NULL
        CHECK (char_length(display_name) BETWEEN 3 AND 20),
    avatar "AssetID",
    activity "Activity" NOT NULL,
    about_me TEXT NOT NULL CHECK (char_length(about_me) <= 2000),
    status TEXT NOT NULL CHECK (char_length(status) <= 200),
    encrypted_secret BYTEA NOT NULL,
    encrypted_state BYTEA NOT NULL
);

CREATE TABLE users_public_keys (
    user_id INT8 REFERENCES users(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    signature_verifier BYTEA NOT NULL,
    box_public_key BYTEA NOT NULL,

    PRIMARY KEY (user_id)
);

-- Information about conversations (DMs or groups)
CREATE TABLE conversations (
    id INT8 PRIMARY KEY,
    epoch INT8 NOT NULL CHECK (epoch >= 0) DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- A table to represent friendships between two users.
-- The constraint and indexing allows for faster checking.
CREATE TABLE friendships (
    user1 INT8 NOT NULL
        REFERENCES users(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    user2 INT8 NOT NULL
        REFERENCES users(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    conversation_id INT8 NOT NULL
        REFERENCES conversations(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    friends_since TIMESTAMPTZ NOT NULL
        DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (user1, user2),

    CONSTRAINT user_id_order CHECK (user1 < user2)
);

CREATE INDEX idx_friendships_user2 ON friendships(user2, user1);

-- A table for pending friend requests.
-- The one-time key is the public OTK that is used for Olm's 3DH.
CREATE TABLE friend_requests (
    sender INT8 NOT NULL
        REFERENCES users(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    receiver INT8 NOT NULL
        REFERENCES users(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    sent_at TIMESTAMPTZ NOT NULL
        DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (sender, receiver)
);

CREATE INDEX idx_friend_requests_receiver ON friend_requests(receiver, sender);

-- Messages sent on the platform.
-- Megolm is used to distribute the decryption keys.
CREATE TABLE messages (
    id INT8 PRIMARY KEY,

    conversation_id INT8 NOT NULL
        REFERENCES conversations(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    parent_id INT8,

    author INT8 NOT NULL
        REFERENCES users(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    blob BYTEA NOT NULL,

    sent_at TIMESTAMPTZ NOT NULL
        DEFAULT CURRENT_TIMESTAMP,

    pinned BOOLEAN NOT NULL
        DEFAULT FALSE,

    UNIQUE (id, conversation_id),

    FOREIGN KEY (parent_id, conversation_id)
        REFERENCES messages(id, conversation_id)
        ON UPDATE CASCADE
        ON DELETE SET NULL
);

-- A table containing the message decryption keys
-- a user has access to
-- (TODO: use this for read receipts?)
CREATE TABLE message_decryption_keys (
    user_id INT8 REFERENCES users(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    message_id INT8 REFERENCES messages(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    blob BYTEA NOT NULL,

    PRIMARY KEY (user_id, message_id)
);

CREATE INDEX idx_message_decryption_keys_message_user ON message_decryption_keys(message_id, user_id);

-- All the members in a DM or group chat and when they joined.
CREATE TABLE conversation_members (
    conversation_id INT8 NOT NULL
        REFERENCES conversations(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    user_id INT8 NOT NULL
        REFERENCES users(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    joined_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (conversation_id, user_id)
);

CREATE INDEX idx_conversation_members_user_id ON conversation_members(user_id, conversation_id);
CREATE INDEX idx_conversation_members_joined_at ON conversation_members(conversation_id, joined_at);

-- Information for a group chat at the database level
CREATE TABLE groups (
    id INT8 NOT NULL
        REFERENCES conversations(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    name TEXT NOT NULL,
    avatar "AssetID",

    invite_code TEXT UNIQUE NOT NULL
        CHECK (invite_code ~ '[0-9A-Z]{8}'),

    locked BOOLEAN NOT NULL
        DEFAULT FALSE,

    PRIMARY KEY (id)
);

-- Any members that were banned from a group chat.
CREATE TABLE group_banned_members (
    group_id INT8 NOT NULL
        REFERENCES groups(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    member_id INT8 NOT NULL
        REFERENCES users(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    banned_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    reason TEXT,

    PRIMARY KEY (group_id, member_id)
);

CREATE INDEX idx_group_banned_members_member_id ON group_banned_members(member_id, group_id);

-- Group session keys and the epochs they are valid for.
CREATE TABLE conversation_session_keys (
    conversation_id INT8 NOT NULL
        REFERENCES conversations(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    epoch INT8 NOT NULL,
    sender INT8 NOT NULL,
    receiver INT8 NOT NULL,
    blob BYTEA NOT NULL,

    PRIMARY KEY (conversation_id, epoch, sender, receiver),

    FOREIGN KEY (conversation_id, sender)
        REFERENCES conversation_members(conversation_id, user_id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    FOREIGN KEY (conversation_id, receiver)
        REFERENCES conversation_members(conversation_id, user_id)
        ON UPDATE CASCADE
        ON DELETE CASCADE
);

-- A table of Megolm messages containing message
-- decryption keys that still need to be handled.
CREATE TABLE pending_message_keys (
    message_id INT8 NOT NULL
        REFERENCES messages(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    epoch INT8 NOT NULL,
    blob BYTEA NOT NULL,

    PRIMARY KEY (message_id, epoch)
);
