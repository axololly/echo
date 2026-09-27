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
    signature_verifier BYTEA NOT NULL
);
