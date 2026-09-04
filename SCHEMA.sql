CREATE TYPE "Activity" AS ENUM(
'Online',
'Idle',
'DoNotDisturb',
'Offline'
);

CREATE DOMAIN "AssetID" AS TEXT CHECK (length(VALUE) = 64);

CREATE TABLE users (
    id INT8 PRIMARY KEY,
    name TEXT UNIQUE CHECK (char_length(name) BETWEEN 3 AND 20),
    display_name TEXT CHECK (char_length(display_name) BETWEEN 3 AND 20),
    avatar "AssetID",
    activity "Activity",
    about_me TEXT CHECK (char_length(about_me) <= 2000),
    status TEXT CHECK (char_length(status) <= 200),
    secret BYTEA -- TODO: add length check
);

CREATE TABLE users_data (
    user_id INT8 REFERENCES users(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    settings BYTEA NOT NULL
);

CREATE TABLE users_crypto (
    user_id INT8 REFERENCES users(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    olm_account BYTEA NOT NULL,

    encryption_public_key BYTEA NOT NULL
        CHECK (length(encryption_public_key) = 32),

    signature_verifier BYTEA NOT NULL
);

CREATE TABLE friendships (
    user1 INT8 REFERENCES users(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    user2 INT8 REFERENCES users(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    friends_since TIMESTAMP NOT NULL,

    PRIMARY KEY (user1, user2),

    CONSTRAINT check_id_order CHECK (user1 < user2)
);

CREATE INDEX idx_friendships_user2 ON friendships(user2);

CREATE TABLE friend_requests (
    sender INT8 REFERENCES users(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    receiver INT8 REFERENCES users(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    one_time_key BYTEA CHECK (length(one_time_key) = 32),

    sent_at TIMESTAMP NOT NULL,

    PRIMARY KEY (sender, receiver)
);

CREATE INDEX idx_friend_requests_receiver ON friend_requests(receiver);

CREATE TABLE conversations (
    id INT8 PRIMARY KEY,
    created_at TIMESTAMP NOT NULL
);

CREATE TABLE groups (
    id INT8 PRIMARY KEY
        REFERENCES conversations(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    name TEXT UNIQUE CHECK (char_length(name) <= 20),
    avatar "AssetID",
    invite_code VARCHAR(8) UNIQUE CHECK (invite_code ~ '^[A-Z0-9]+$'),
    current_epoch INT8 NOT NULL CHECK (current_epoch >= 0)
);

CREATE TABLE conversation_members (
    conversation_id INT8 NOT NULL
        REFERENCES conversations(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    user_id INT8 REFERENCES users(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    joined_at TIMESTAMP NOT NULL,

    PRIMARY KEY (conversation_id, user_id)
);

CREATE INDEX idx_conversation_member_ids ON conversation_members(user_id);

CREATE TABLE group_banned_members (
    group_id INT8 NOT NULL
        REFERENCES groups(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    user_id INT8 NOT NULL
        REFERENCES users(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    PRIMARY KEY (group_id, user_id)
);

CREATE INDEX idx_group_banned_member_ids ON group_banned_members(user_id);

CREATE TYPE "MessageType" AS ENUM(
    'Normal',
    'Reply',
    'Edit'
);

CREATE TABLE messages (
    id INT8 PRIMARY KEY,

    parent_id INT8
        REFERENCES messages(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    conversation_id INT8 NOT NULL
        REFERENCES conversations(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    author_id INT8 NOT NULL
        REFERENCES users(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    type "MessageType" NOT NULL,

    sent_at TIMESTAMP NOT NULL,

    blob BYTEA NOT NULL
);

CREATE INDEX idx_messages_conversation_id ON messages(conversation_id, id);
CREATE INDEX idx_messages_author_id ON messages(author_id);

-- TODO: make this work too
-- CREATE TABLE asset_decryption_keys (
--     user_id INT8 NOT NULL
--         REFERENCES users(id)
--         ON UPDATE CASCADE
--         ON DELETE CASCADE,
--
--     asset_id "AssetID",
--
--     asset_key BYTEA NOT NULL,
--
--     PRIMARY KEY (user_id, asset_id)
-- );

-- Each user stores the key that decrypts the message
-- encrypted under their own master secret.
CREATE TABLE message_decryption_keys (
    user_id INT8 NOT NULL
        REFERENCES users(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    message_id INT8 NOT NULL
        REFERENCES messages(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    blob BYTEA NOT NULL,

    PRIMARY KEY (user_id, message_id)
);

CREATE INDEX idx_message_decryption_keys_id ON message_decryption_keys(message_id);

-- CREATE TABLE asset_decryption_keys (
--     user_id INT8 NOT NULL
--         REFERENCES users(id)
--         ON UPDATE CASCADE
--         ON DELETE CASCADE,

--     asset_id "AssetID",

--     asset_key BYTEA NOT NULL,

--     PRIMARY KEY (user_id, asset_id)
-- );

-- These are Olm/Megolm messages containing decryption keys
-- that need to be added to the 'message_decryption_keys' table.
CREATE TABLE outgoing_message_keys (
    message_id INT8 NOT NULL
        REFERENCES messages(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    recipient_id INT8 NOT NULL,

    epoch INT8 NOT NULL CHECK (epoch >= 0),

    blob BYTEA NOT NULL,

    PRIMARY KEY (recipient_id, epoch, message_id)
);

CREATE INDEX idx_outgoing_messages_id ON outgoing_message_keys(message_id);

-- These are Megolm session keys used for transporting the message keys.
CREATE TABLE group_session_keys (
    group_id INT8 NOT NULL
        REFERENCES groups(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    epoch INT8 NOT NULL CHECK (epoch >= 0),

    sender_id INT8 NOT NULL
        REFERENCES users(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    recipient_id INT8 NOT NULL
        REFERENCES users(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    blob BYTEA NOT NULL,

    PRIMARY KEY (group_id, epoch, sender_id, recipient_id)
);

CREATE INDEX idx_group_session_keys_recipient ON group_session_keys(recipient_id, group_id, epoch);
