//! Single integration-test binary: each module is a former `tests/*.rs` crate.
//! One binary links dependencies once; nextest still runs every test in its own process.
//! Add each new integration-test file here as a module.

#[path = "../protocol.rs"]
mod protocol;
