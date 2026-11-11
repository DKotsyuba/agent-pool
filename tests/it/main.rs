//! Single integration-test binary: each module is a former `tests/*.rs` crate.
//! One binary links dependencies once; nextest still runs every test in its own process.

#[path = "../installer.rs"]
mod installer;
#[path = "../protocol.rs"]
mod protocol;
