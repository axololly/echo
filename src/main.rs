mod id;
use id::{SnowflakeID, SNOWFLAKE_GEN};

mod secret;
use secret::{Encrypted, Secret};

use std::collections::HashMap;

use rootcause::Result;
use vodozemac::olm::{Account, OlmMessage, Session, SessionConfig};

const CONFIG: SessionConfig = SessionConfig::version_1();

struct User {
    id: u64,
    secret: Secret,
    olm: Account
}

impl User {
    pub fn new(id: u64) -> Self {
        Self {
            id,
            secret: Secret::random(),
            olm: Account::new()
        }
    }
}

struct DmSession {
    author: u64,
    author_secret: Secret,
    other: u64,
    inner: Session
}

struct Message {
    id: SnowflakeID,
    from: u64,
    to: u64,
    data: String
}

impl DmSession {
    pub fn send(&mut self, msg: &str) -> (Encrypted<String>, OlmMessage) {
        let olm = self
            .inner
            .encrypt(msg)
            .expect("failed to encrypt message");

        let enc = self
            .author_secret
            .encrypt(&msg)
            .cast::<String>();

        (enc, olm)
    }
}

fn make_sessions(user1: &mut User, user2: &mut User) -> (DmSession, DmSession) {
    let otk = user1.olm.generate_one_time_keys(1).created[0];

    let mut user2_session = user2
        .olm
        .create_outbound_session(
            CONFIG,
            user1.olm.curve25519_key(),
            otk
        )
        .expect("failed to make outbound session");

    let raw_msg = user2_session
        .encrypt([])
        .expect("failed to encrypt empty message");

    let OlmMessage::PreKey(prekey) = raw_msg else {
        unreachable!()
    };

    let user1_session = user1
        .olm
        .create_inbound_session(
            CONFIG,
            user2.olm.curve25519_key(),
            &prekey
        )
        .expect("failed to create inbound session")
        .session;

    let s1 = DmSession {
        author: user1.id,
        author_secret: user1.secret,
        other: user2.id,
        inner: user1_session
    };

    let s2 = DmSession {
        author: user2.id,
        author_secret: user2.secret,
        other: user1.id,
        inner: user2_session
    };

    (s1, s2)
}

struct MessageEntry {
    sender_copy: Encrypted<String>,
    olm_message: OlmMessage
}

fn main() -> Result<()> {
    let mut message_db: HashMap<(u64, SnowflakeID), MessageEntry> = HashMap::new();

    let mut alice = User::new(1);
    let mut bob = User::new(1);

    let (
        mut alice_to_bob,
        mut bob_to_alice
    ) = make_sessions(&mut alice, &mut bob);

    let (alice_copy, alice_msg) = alice_to_bob.send("hello bob");

    message_db.insert()

    Ok(())
}
