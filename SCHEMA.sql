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

CREATE TABLE users_crypto (
    olm_account BYTEA,
    settings BYTEA,
    signature_verifier BYTEA CHECK (length(signature_verifier) = 32)
);

CREATE TABLE friendships (
    user1 INT8 REFERENCES users(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    user2 INT8 REFERENCES users(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    PRIMARY KEY (user1, user2),

    CONSTRAINT check_id_order CHECK (user1 < user2)
);

CREATE INDEX idx_friendships_user2 ON friendships(user2);

CREATE TABLE groups (
    id INT8 PRIMARY KEY,
    name TEXT UNIQUE CHECK (char_length(name) <= 20),
    avatar "AssetID",
    invite_code VARCHAR(8) UNIQUE CHECK (invite_code ~ '^[A-Z0-9]+$')
);

CREATE TABLE group_members (
    group_id INT8 REFERENCES groups(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    user_id INT8 REFERENCES groups(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    joined_at TIMESTAMP NOT NULL,

    PRIMARY KEY (group_id, user_id)
);

CREATE INDEX idx_group_member_ids ON group_members(user_id);
