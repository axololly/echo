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
    avatar "AssetID" NOT NULL,
    activity "Activity" NOT NULL,
    about_me TEXT NOT NULL
        CHECK (char_length(about_me) <= 2000),
    status TEXT NOT NULL
        CHECK (char_length(status) <= 200),
    encrypted_secret BYTEA NOT NULL,
    encrypted_state BYTEA NOT NULL,
    signature_verifier BYTEA NOT NULL,
    olm_account BYTEA NOT NULL,
    olm_public_key BYTEA NOT NULL
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

    one_time_key BYTEA NOT NULL
        CHECK (length(one_time_key) = 32),

    sent_at TIMESTAMPTZ NOT NULL
        DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (sender, receiver)
);

CREATE INDEX idx_friend_requests_receiver ON friend_requests(receiver);

-- For the other person to complete their session, they have to
-- read a pre-key message. These messages are stored here, and
-- once used to establish a session, they are discarded and the
-- new session is put in the dm_sessions table.
CREATE TABLE pending_dm_sessions (
    waiting_on INT8 NOT NULL
        REFERENCES users(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    other INT8 NOT NULL
        REFERENCES users(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    pre_key_msg BYTEA NOT NULL,

    PRIMARY KEY (waiting_on, other)
);

-- Created Olm sessions, along with who they're owned
-- by and who they are communicating to
--
-- (TODO: prevent misuse from changing the other ID)
CREATE TABLE dm_sessions (
    owner INT8 NOT NULL
        REFERENCES users(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    other INT8 NOT NULL
        REFERENCES users(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    blob BYTEA NOT NULL,

    PRIMARY KEY (owner, other)
);

-- Messages sent through a DM.
-- These are encrypted blobs and the decryption keys
-- are distributed through Olm.
CREATE TABLE dm_messages (
    id INT8 PRIMARY KEY,

    sender INT8 NOT NULL
        REFERENCES users(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    receiver INT8 NOT NULL
        REFERENCES users(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    blob BYTEA NOT NULL,

    sent_at TIMESTAMPTZ NOT NULL
        DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_dm_messages_id_sender_receiver ON dm_messages(id, sender, receiver);
CREATE INDEX idx_dm_messages_id_receiver ON dm_messages(id, receiver);
CREATE INDEX idx_dm_messages_receiver ON dm_messages(receiver, id);

-- A table containing the message decryption keys
-- a user has access to
-- (TODO: use this for read receipts?)
CREATE TABLE message_decryption_keys (
    message_id INT8,

    user_id INT8 REFERENCES users(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    blob BYTEA NOT NULL,

    PRIMARY KEY (message_id, user_id)
);

CREATE INDEX idx_message_decryption_keys_user ON message_decryption_keys(user_id, message_id);

-- A table of Olm messages containing decryption keys
-- that have not been opened by the other party
CREATE TABLE unread_dm_messages (
    message_id INT8 REFERENCES dm_messages(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    waiting_on INT8 NOT NULL
        REFERENCES users(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    blob BYTEA NOT NULL,

    PRIMARY KEY (message_id, waiting_on)
);
