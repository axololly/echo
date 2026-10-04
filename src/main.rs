use serde::Serialize;
use vodozemac::{megolm::{GroupSession, SessionConfig as MegolmSessionConfig}, olm::{Account, OlmMessage, SessionConfig}};

const CONFIG: MegolmSessionConfig = MegolmSessionConfig::version_1();

/// Serialize some data using [`bitcode`],
/// then measure and return the size of the
/// serialized payload.
fn size_of<T: Serialize>(data: &T) -> usize {
    bitcode::serialize(data).unwrap().len()
}

fn main() -> rootcause::Result<()> {
    let group_session = GroupSession::new(CONFIG);

    let pickle_size = size_of(&group_session.pickle());
    let session_key_size = size_of(&group_session.session_key());

    println!("size of group session pickle: {pickle_size} bytes");
    println!("size of session key: {session_key_size} bytes");

    Ok(())
}
