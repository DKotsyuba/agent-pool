//! Read bounded example provider JSON from stdin and print compact agent text.
//! This executable performs no provider calls or mutations.
use mcp_presentation::{MAX_SOURCE_BYTES, Renderer};
use std::io::{self, Read, Write};
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut raw = Vec::new();
    if io::stdin()
        .lock()
        .take((MAX_SOURCE_BYTES + 1) as u64)
        .read_to_end(&mut raw)
        .is_err()
    {
        eprintln!("Cannot read example input.");
        return ExitCode::FAILURE;
    }
    let renderer = match Renderer::new() {
        Ok(renderer) => renderer,
        Err(_) => {
            eprintln!("Cannot register embedded templates.");
            return ExitCode::FAILURE;
        }
    };
    let reply = renderer.jobs_json(&raw);
    if io::stdout()
        .lock()
        .write_all(reply.text().as_bytes())
        .is_err()
    {
        return ExitCode::FAILURE;
    }
    if reply.is_error() {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    }
}
