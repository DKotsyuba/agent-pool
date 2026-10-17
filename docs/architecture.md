# Architecture

Candidate profile: in-process + no state, stdio MCP, no host adapter.

The authoritative tool registry is Rust code in `src/tools/mod.rs`;
`schemas/tools.json` is an exported discovery snapshot, not a load path.
Responses are rendered from small typed views through the embedded MiniJinja
renderers in `crates/mcp-presentation` and `src/response.rs` per
`docs/MCP_RESPONSE_STANDARD.md`.

The executable ships its own installer: `self-install` and `releases` manage
immutable version directories under the product home and never touch anything
outside the declared home and bin directory.

Replace this file with the product's real architecture — modules, state,
boundaries and refusal rules — as behavior is implemented. The generated shape
is deliberately small and does not encode a multi-crate runtime framework.
