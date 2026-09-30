 -- TODO: add length checks to BYTEA columns

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
    avatar "AssetID" NOT NULL,
    activity "Activity" NOT NULL,
    about_me TEXT CHECK (char_length(about_me) <= 2000),
    status TEXT CHECK (char_length(status) <= 200),
    encrypted_secret BYTEA NOT NULL,
    encrypted_state BYTEA NOT NULL,
    signature_verifier BYTEA NOT NULL,
    olm_account BYTEA NOT NULL,
    olm_public_key BYTEA NOT NULL
);

CREATE TABLE friendships (
    user1 INT8 REFERENCES users(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    user2 INT8 REFERENCES users(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    friends_since TIMESTAMPTZ NOT NULL
        DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (user1, user2),

    CONSTRAINT user_id_order CHECK (user1 < user2)
);

CREATE INDEX idx_friendships_user2 ON friendships(user2, user1);

CREATE TABLE friend_requests (
    sender INT8 REFERENCES users(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    receiver INT8 REFERENCES users(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    one_time_key BYTEA NOT NULL
        CHECK (length(one_time_key) = 32),

    sent_at TIMESTAMPTZ NOT NULL
        DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (sender, receiver)
);

CREATE INDEX idx_friend_requests_receiver ON friend_requests(receiver);

CREATE TABLE pending_dm_sessions (
    waiting_on INT8 REFERENCES users(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    other INT8 REFERENCES users(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    pre_key_msg BYTEA NOT NULL,

    PRIMARY KEY (waiting_on, other)
);

CREATE TABLE dm_sessions (
    owner INT8 REFERENCES users(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    other INT8 REFERENCES users(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    session BYTEA NOT NULL,

    PRIMARY KEY (owner, other)
);
