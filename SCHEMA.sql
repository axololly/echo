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
    encrypted_secret BYTEA, -- TODO: add length check
    encrypted_state BYTEA,
    signature_verifier BYTEA CHECK (length(signature_verifier) = 32)
);

CREATE TABLE friendships (
    user1 INT8 REFERENCES users(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    user2 INT8 REFERENCES users(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE
);

CREATE TABLE groups (
    id INT8 PRIMARY KEY,
    name TEXT UNIQUE CHECK (char_length(name) <= 20),
    avatar "AssetID"
);

CREATE TABLE group_members (
    group_id INT8 REFERENCES groups(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    user_id INT8 REFERENCES groups(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    joined_at TIMESTAMP NOT NULL
);
