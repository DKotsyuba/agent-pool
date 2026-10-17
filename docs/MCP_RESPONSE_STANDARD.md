# Rust MCP response and MiniJinja standard

**Profile:** `rust-minijinja-v1` · **Revision:** 0.1.0 · **Date:** 2026-09-28

**Status:** proposed normative extension to Agent MCP Family Standard 1.0.0-rc.2. Merging this extension adopts the rules for new template-derived work; it does not certify existing products or silently change their public contracts.

## 1. Purpose and precedence

An agent must be able to determine what happened, what it can safely do next, and whether any important information is missing without reading an upstream API response. Compactness means removing irrelevant data, not removing evidence, uncertainty, identifiers or necessary instructions.

**RESP-01 — MUST.** Product code and presentation code are Rust. Repository automation is Rust `xtask`; small Bash/POSIX shell launchers are allowed. MiniJinja is an embedded Rust library, not Python Jinja2. No Python interpreter, pip, Node or separate template compiler is required.

This profile supplements the family standard's Rust policy and MCP rules. Within presentation, it takes precedence over the earlier optional MiniJinja/`format!` guidance. Normal agent-facing tool layouts use reviewed MiniJinja templates; fixed bootstrap errors, protocol errors and emergency fallback may use static Rust strings or narrowly scoped `format!`. Earlier references to a Python devkit are superseded by the merged Rust-only policy.

Numbers below are family policy defaults, not MCP limits or measured tokenizer characteristics. Rule compliance and implementation/qualification status must be reported separately.

## 2. The pipeline

```text
bounded external bytes / local typed result
    -> adapter: deserialize and validate external DTO
    -> application: determine outcome, effects and recovery
    -> presenter: choose and bound an allowlisted view
    -> MiniJinja: lay out that view as plain text
    -> bounded UTF-8 buffer
    -> MCP adapter: text block + independent isError
```

**RESP-02 — MUST.** These responsibilities remain separate, even when implemented as modules in one crate. No daemon, database, global framework or crate-per-layer is required. A small local presentation crate is useful when its contract tests should run independently of MCP/network code; it is not a mandatory architecture for all products.

**RESP-03 — MUST NOT.** Do not implement a generic recursive JSON-to-text dumper as the production presenter. Removing braces or flattening every key does not identify which facts the agent needs. A huge JSON object with different punctuation is still a huge object.

For results created inside Rust, pass the typed result directly to the presenter. Do not serialize it to JSON and immediately deserialize it merely to follow this diagram.

### Boundary responsibilities

| Layer | Owns | Must not do |
|---|---|---|
| External DTO | Upstream field names, required fields, decoding | Decide that missing data means success |
| Application result | Outcome, identity, confirmed effects, partial failures, retry/recovery | Contain formatted MCP prose |
| Presentation view | Relevant fields, ordering, display-safe strings, page metadata | Perform I/O, change business state or infer authorization |
| Template | Fixed wording, optional sections, bounded row layout | Parse raw JSON, retry requests, compute workflow rules |
| MCP adapter | Wire result, `isError`, content profile | Recover semantic status by parsing the rendered text |

A DTO normally derives `Deserialize`, a view derives `Serialize`, and domain types use explicit Rust enums/newtypes. Do not derive `Serialize` on credential-bearing DTOs just to pass them to the renderer. `serde_json::Value` is acceptable at a genuinely dynamic adapter boundary; it is not the default application model or template context.

## 3. External JSON is not a trusted result

**RESP-04 — MUST.** Bound bytes before JSON decoding and check required fields and types. An absent `items` is not an empty list; an absent status is not `ok`; a missing total is not zero. Unknown extra upstream fields may be ignored deliberately so upstream additions do not break unrelated reads. Unknown enum variants must become an explicit unknown/error state, never success.

A useful division is tolerant external DTOs with required critical fields, followed by strict internal validation. Use `#[serde(deny_unknown_fields)]` for owned contracts such as tool arguments or configuration where the contract requires it, not indiscriminately on every external response.

A successful HTTP status does not establish successful application execution. An adapter for an API that can return data and errors together must preserve partialness. If a write might have reached the provider before a malformed response or timeout, classify its effect as uncertain; do not report that nothing happened.

**RESP-05 — MUST.** Preserve these distinct facts whenever they affect the next action: absent, null, empty, zero, false, not checked, not available, and not applicable. Do not use truthiness to hide `tests_passed = 0`, `merged = false` or an explicitly empty result.

Malformed JSON and schema errors produce a stable safe code. Never echo the rejected upstream body or the deserializer's arbitrary source excerpt to the model.

## 4. Execution status and presentation status

**RESP-06 — MUST.** Determine semantic outcome and `isError` before rendering. A template has no authority to turn a failure into success or a confirmed mutation into an uncertain one. Presentation degradation is an independent condition.

| Application outcome | Agent meaning | Default `isError` |
|---|---|---|
| `ok` | Requested read/computation completed | false |
| `committed` | Requested mutation confirmed | false |
| `noop` | Desired state already held; no new effect | false |
| `pending` | Work accepted, not completed; valid handle required | false |
| `partial` | Only some requested information/work completed | Declared per tool, based on whether its requested goal failed |
| `blocked` | Preconditions or authorization prevent the operation | true |
| `unavailable` | Needed capability/provider is unavailable | true |
| `outcome_unknown` | An effect may have happened; reconciliation required | true |

This is a new-product vocabulary, not permission to rename existing product statuses in a patch release. The presentation library example supports a subset; unsupported cases require product-specific implementation.

Protocol failures and tool execution failures are different MCP channels. Input errors the agent can correct generally use an execution-error result; malformed protocol messages and unknown tools use the declared protocol error route. The exact wire shape follows the pinned SDK and supported protocol revision, not a handcrafted generic JSON-RPC implementation. [MCP]

## 5. What an agent should see

**RESP-07 — MUST.** The response preserves enough information to choose the next safe action. In order of priority:

1. Outcome and relevant object/operation identifier.
2. Requested answer, actual change, or reason for refusal.
3. Material limits: incomplete result, stale observation, unverified checks or uncertain effect.
4. A valid continuation or safe recovery step when needed.

Usually this is a short header and a few lines, not a paragraph introducing the tool, an essay about the schema, or a repeated copy of the request.

**RESP-08 — SHOULD.** Use plain UTF-8 text, stable labels, short sentences or compact labelled rows. Put the result first. No greetings, apologies for routine errors, congratulations, progress narration, decorative emoji, ASCII boxes or large Markdown tables. Agent-facing control text is English; quoted user content stays in its original language.

Use one text block for a text-only tool by default. This is family policy, not a restriction on MCP's ability to return multiple blocks or non-text content.

### What to keep or omit

| Keep when relevant | Omit by default |
|---|---|
| Stable IDs required for subsequent calls | Duplicated nested parent objects |
| Actual status and confirmed changed fields | Provider transport envelopes and headers |
| Reason, failed precondition, validation field | Null optional metadata with no decision value |
| Explicit uncertainty and omitted-content indicator | Internal typename, connection wrappers, debug traces |
| Unit, comparison baseline and freshness when material | Repeated timestamps and request arguments |
| Exact path/range/revision for code work | Full document body after a save acknowledgement |
| Continuation accepted by an existing retrieval route | A second full JSON copy of the same answer |

**RESP-09 — MUST.** Do not silently shorten action-critical values: IDs, request IDs, cursors, revision hashes, paths used by tools, code that will be applied, or required recovery parameters. Friendly labels can be shortened with an explicit marker, but an abbreviated label must not become an identifier.

Long data is not inherently irrelevant. A request to read source code, a document or a diff needs faithful content through a suitable bounded retrieval path, not an invented summary in place of the requested bytes.

## 6. Canonical response forms

These are layout conventions, not a parser grammar. Programs use structured output, never regex over these examples. Tool names in this section are illustrative and must be replaced with names actually exported by each product.

### Acknowledgement

```text
COMMITTED task T-42
Changed: status=done; result=recorded
```

No complete task object and no repeated description. For a no-op:

```text
NOOP task T-42
Status was already done; no changes made.
```

### Read/list

```text
OK jobs: 2 returned; more=true
ag-17 | running | "Fix token refresh"
ag-18 | failed | "Run integration tests"
Cursor: page-2
```

`2 returned` describes this page, not an unverified global total. Preserve the provider's meaningful order; sort in Rust only when the ordering contract explicitly says to do so.

### Pending

```text
PENDING operation op-19
Accepted; completion has not been confirmed.
Next: inspect_operation operation_id=op-19
```

Only emit this if admission and the handle are real. A request still executing synchronously is not an admitted durable job.

### Expected refusal

```text
ERROR precondition_failed: module M-8 cannot be closed.
Blocking: task T-42 is in_progress.
Next: finish or explicitly reschedule T-42, then retry closing M-8.
```

The presenter copies a verified precondition failure; it does not discover workflow rules inside a template.

### Unknown write outcome

```text
OUTCOME_UNKNOWN request req-19
The provider may have applied the change; confirmation was not received.
Next: reconcile this request_id. Do not create a replacement request.
```

Never replace this with a generic retry instruction.

### Partial read

```text
PARTIAL diagnostics: 8 errors, 2 warnings in the scanned files
Coverage: Rust checked; TypeScript checker unavailable.
```

Do not say "workspace has 8 errors" when only part of the workspace was checked. A missing checker is not a passed check.

### Next-step policy

**RESP-10 — MUST.** `Next:` is optional and must be safe, relevant, and possible. Emit at most one recommended step. Do not repeat a complete workflow manual, invent a tool/resource, claim background wake is guaranteed, or recommend replaying a non-idempotent write. Recovery text is selected by Rust from an application-level recovery policy, not from untrusted provider prose.

## 7. Budgeting and pagination

**RESP-11 — MUST.** Each tool declares byte, row and content budgets separately from its MCP discovery schema. Suggested starting defaults:

| Result class | Normal target | Default hard text cap |
|---|---:|---:|
| Mutation acknowledgement / routine error | 1–8 lines | 2 KiB |
| Status / compact entity | 3–20 lines | 4 KiB |
| Search/list page | 10–20 rows | 8 KiB |
| Context, source, diff or document excerpt | Use a justified product profile | 16 KiB before continuation |

These are UTF-8 byte limits on rendered text. They are not token limits; token cost depends on tokenizer, language, identifiers and content. Measure encoded MCP envelope size separately when the transport requires it. No automatic claim of a fixed percentage of token savings.

**RESP-12 — MUST.** Budget the view before rendering: select allowed fields, cap the upstream page, shorten only descriptive labels, and reserve space for headers, warnings and continuation. Then render to a bounded writer. Render into a private buffer; publish it only on success. Do not stream a partially rendered template onto MCP stdout.

A post-render `text[..limit]`, `.take(limit)` on the final answer, or removal of the last lines is not an acceptable budget strategy. It may cut an identifier, UTF-8 sequence, safety warning, closing delimiter or continuation.

**RESP-13 — MUST.** Never skip unseen rows while presenting pagination. If 50 upstream rows arrived but only 10 were displayed, the upstream next-page cursor starts after row 50, not row 10. Valid choices are:

- request a smaller upstream page so all rows fit;
- expose a bounded continuation that resumes inside that page and preserves its snapshot/ordering contract;
- return an explicit refusal to present the oversized page and request narrower input.

The reference library uses the last option for more than 20 incoming rows. It never silently slices a page and then emits the provider's cursor. Large documents and diffs require real range/detail retrieval, including authorization, expiry and stale-snapshot behavior; a fabricated `detail_ref` is not a solution.

## 8. MiniJinja engine policy

**JINJA-01 — MUST.** Templates are trusted, versioned application assets. Embed them with `include_str!`; register a closed set when the process starts. User input, repository content, provider responses and runtime configuration must not become template source, a template name, an include path or an expression to evaluate.

The normative baseline for this profile is the explicitly reviewed `minijinja =2.24.0` API. Keep a reviewed Cargo.lock. The compiler and `rmcp =3.4.0` baseline remain unchanged. For MCP 2026-07-28, the catalog handler explicitly supplies `ttlMs = 60000` and `cacheScope = "private"`; legacy responses omit these fields. Raw stdio tests cover modern tools/list and server/discover without initialize, plus the legacy handshake route. Cacheable list/read results on any enabled prompts/resources surface require the same revision-appropriate hints. The crate's feature definitions and APIs were inspected in its tagged upstream source. [MJ-FEATURES] [MJ-TEMPLATE]

```toml
[workspace.dependencies]
minijinja = { version = "=2.24.0", default-features = false, features = ["serde", "fuel"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

**JINJA-02 — MUST.** Start with the smallest feature set used by the chosen templates. `serde` enables typed views; this implementation uses `fuel`. Add `macros` and `multi_template` only when real shared templates need them. Do not enable `loader`, `json`, `debug` or every default feature out of habit. `json` is not needed merely because upstream data arrived as JSON. [MJ-FEATURES]

The closed reference environment uses `Environment::empty()`, so no implicit filters, functions or globals are installed. A product can instead explicitly register a reviewed set of formatting-only helpers. Enabling a feature is not a substitute for registering/testing the environment configuration.

```rust
let mut env = minijinja::Environment::empty();
env.set_undefined_behavior(minijinja::UndefinedBehavior::Strict);
env.set_auto_escape_callback(|_| minijinja::AutoEscape::None);
env.set_trim_blocks(true);
env.set_lstrip_blocks(true);
env.set_keep_trailing_newline(true);
env.set_recursion_limit(16);
env.set_fuel(Some(50_000));
```

**JINJA-03 — MUST.** Strict undefined behavior is mandatory. Missing required view variables fail rendering; optional values are explicitly represented and guarded. Do not paper over a required status, identifier or page field with `default('ok')`, `default('')` or `unwrap_or_default()` upstream. Parse-time success does not prove that every branch renders: use representative fixtures. [MJ-ENV]

**JINJA-04 — MUST.** Output is plain text. Explicit `AutoEscape::None` avoids accidental HTML entities. It is not a security sanitizer. Keep user data safe through projection, quoting and field-specific policies before rendering. Do not use `|safe` as a general trust mechanism.

**JINJA-05 — MUST.** The environment is immutable after startup and reused; a renderer has no HTTP client, filesystem loader, shell execution, clock or access to secrets. Custom filters must be pure, bounded and deterministic. No callback may fetch details, retry a write, read an environment variable or start a process.

**JINJA-06 — SHOULD.** Keep templates to interpolation, short conditionals and loops over already bounded rows. Shared macros may encode repeated display structure, not business decisions. Sorting, counts, permission checks, retry policy, status mapping, redaction and pagination stay in Rust.

Fuel limits VM instructions, not elapsed time or total allocation; a custom function can still do expensive work. Bound input/view/output independently. Do not describe fuel or plain-text escaping as a sandbox. The reference uses `render_captured_to` with an `io::Write` cap; `render_to_write` is deprecated in this inspected API. [MJ-ENV] [MJ-TEMPLATE]

## 9. Typed views and template contracts

**VIEW-01 — MUST.** Give each response family an explicit view type: acknowledgement, entity, page, diagnostics, excerpt and error. Reuse a small set of layouts when their semantics match; do not write one universal template with a hundred optional JSON keys.

```rust
#[derive(serde::Serialize)]
struct JobsView {
    returned: usize,
    has_more: bool,
    unknown_statuses: usize,
    rows: Vec<JobRowView>,
    cursor: Option<String>,
}

#[derive(serde::Serialize)]
struct JobRowView {
    id: String,       // validated, exact, never truncated
    state: &'static str,
    title: String,    // display-safe quoted label, not raw provider content
}
```

The template receives this projection, not a credential-bearing DTO or the complete domain graph. Optional fields are serialized explicitly; avoid `skip_serializing_if` when a strict template expects to test that field.

```jinja
OK jobs: {{ returned }} returned; more={{ has_more }}
{% for row in rows %}
{{ row.id }} | {{ row.state }} | {{ row.title }}
{% endfor %}
{% if cursor %}
Cursor: {{ cursor }}
{% endif %}
```

**VIEW-02 — MUST.** Template selection is a Rust enum or closed match on an owned operation kind. Arbitrary template names are not tool arguments. Build the environment before admitting mutating work. Cache no per-user context globally; the reusable environment is not permission to reuse a previous caller's view.

The serialization boundary is an allowlist, not just an implementation convenience. Adding a field to an upstream DTO must not automatically expose it in an agent reply.

## 10. Untrusted text, secrets and exactness

**SAFE-01 — MUST.** Credentials and confidential fields are removed by allowlisted projection before they reach MiniJinja. Redaction after rendering is only secondary defense. The same restrictions apply to structured output, metrics, error chains and logs. Do not assume the presence of a property named `token` is the only way secrets appear: a title or document can itself contain sensitive data, so visibility/redaction decisions belong at the product boundary.

**SAFE-02 — MUST.** Distinguish display labels from actionable references and exact content:

- Display labels: quote/escape line breaks, delimiters and control/bidirectional-format characters; shorten with an explicit marker if necessary.
- Actionable IDs/cursors: validate against their declared alphabet/length or use an unambiguous reversible encoding; never silently normalize or truncate them.
- Source/document/diff excerpts: preserve exact relevant content; use labelled boundaries and range/revision metadata. Display-safe escaping is not permission to change bytes the agent is supposed to apply. Provide exact retrieval separately when a channel cannot safely carry those bytes.

The reference renders titles as JSON-quoted strings, not as raw JSON objects. This preserves single-line boundaries and visible escape sequences. It does not evaluate literal `{{ ... }}` supplied in data. Bidi formatting characters are made visible. This reduces structural spoofing but does not solve semantic prompt injection: hostile text remains untrusted evidence, not instructions. No renderer can guarantee that an LLM will ignore malicious natural-language content.

**SAFE-03 — MUST.** Do not emit arbitrary clickable provider URLs, terminal escape sequences, Markdown links or executable next-step commands without validating them for the channel. A plain-text renderer must not become a command-construction helper. Never pass rendered text to a shell.

## 11. Failure of presentation after success of execution

**FAIL-01 — MUST.** A renderer failure cannot undo an external effect. Keep an immutable execution receipt outside the template context: semantic status, known object identity, request identity and safe recovery class. On template/fuel/output failure, discard the partial rendered buffer and produce a small Rust fallback from that receipt.

Confirmed write:

```text
COMMITTED entity T-42
Request: req-19
Presentation: degraded (presentation_failed).
Do not repeat the mutation to repair this response.
```

Unknown write:

```text
OUTCOME_UNKNOWN request req-19
Presentation: degraded (presentation_failed).
Reconcile this request_id before any retry.
```

A usable fallback for a confirmed mutation preserves `isError=false`; a side-effect outcome that was unknown remains unknown with `isError=true`. A read whose requested information could not be presented may use `isError=true`. Where an essential receipt itself cannot be represented within the response budget, the product must define a separate recovery/error route; do not claim a generic fallback solved it.

**FAIL-02 — MUST NOT.** Never fall back to pretty-printing raw JSON, `Debug` of a context/DTO/error, or detailed MiniJinja error source. Do not automatically rerun application logic because formatting failed. Safe local diagnostics may record template ID, stable error category, event ID and byte counts, but not the raw context.

Embedded template syntax errors should fail startup or registration before a write can be admitted. Runtime shape/branch failures still need status-preserving fallback; startup parsing alone is insufficient.

## 12. Structured results and MCP compatibility

**WIRE-01 — MUST.** Separate the internal structured result from what the model sees. The internal model always stays typed. Text-first tools do not require `structuredContent` merely because their provider returned JSON.

For an agent-only tool, the default is one compact text block without `outputSchema`. For a genuine machine consumer, expose a stable allowlisted structured contract through MCP or CLI JSON. If MCP `outputSchema` is declared, return conforming `structuredContent`; plain text alone is not enough. Test success and error variants or define their protocol routes explicitly. [MCP]

The inspected MCP specification recommends serialized JSON in a text block for backward compatibility when structured content is returned. A compact-text-plus-structured profile must document why its supported hosts do not require that duplication. A compatibility profile requiring JSON text uses a small public result schema, not the full upstream payload plus another full prose copy. This is a reasoned compatibility choice, not a claim that duplicate JSON is forbidden by MCP. [MCP]

**WIRE-02 — MUST.** `isError`, structured fields and prose refer to the same immutable outcome. They are not independently inferred. Never rely on an undocumented host automatically hiding `structuredContent` from the model. Discover output schemas through the actual SDK/host combination.

The normal text layer is not a replacement for image, resource or exact-content outputs when those are necessary for the tool's purpose.

## 13. Rust engineering rules

**RUST-P01 — MUST.** Workspace dependencies centralize common versions/features; member crates opt in explicitly. Cargo applications commit Cargo.lock. The toolchain is pinned, while `rust-version` describes the supported minimum. Resolver 3 and edition 2024 are the existing family baseline. [CARGO]

**RUST-P02 — MUST.** Production presentation code must not use `unwrap`, `expect`, `panic!`, `todo!` or `unimplemented!` for runtime failures. Use typed errors and checked conversions. Narrow allowances in tests are permitted with a reason. The presentation crate forbids unsafe code; platform FFI elsewhere requires a separate documented boundary.

**RUST-P03 — MUST.** No I/O or mutation in projection/rendering. Use owned or borrowed immutable values and ordinary functions. Avoid traits/generics that add no useful substitution boundary. The reference local crate has no Tokio, rmcp, HTTP, storage or filesystem dependency.

**RUST-P04 — SHOULD.** Prefer public API documentation, `#[must_use]` for reply-producing functions, stable error categories and `TryFrom`/validated newtypes for important boundaries. Do not spread direct access such as `value["data"]["status"].as_str().unwrap_or("ok")` through handlers.

**RUST-P05 — MUST.** Keep one quality gate, `cargo xtask check`, running formatter, Clippy, tests and rustdoc. A focused `cargo xtask test presentation` is an additional entrypoint, not a weaker replacement. No Python test runner, snapshot updater or template precompiler.

Feature checks must reflect supported combinations. `--all-features` is not a substitute for testing minimal supported features, and it must not silently activate live/mutating tests. For mutually exclusive features use an explicit matrix. Dependency/license/advisory checks remain a separate network-prepared cargo-deny gate; this presentation change does not claim that the previously missing supply-chain pipeline is now implemented.

## 14. Required tests

**TEST-01 — MUST.** Tests are Rust tests using local fixtures. Snapshot changes are reviewed diffs, not blindly accepted output. At minimum cover:

| Case | Required invariant |
|---|---|
| Valid raw JSON | Exact expected compact output |
| Unknown unrelated upstream fields | No automatic exposure |
| Malformed JSON / missing critical field | Stable error, never empty success |
| Empty list; zero; false; null | Their meaningful distinctions remain |
| Unknown source status | Never mapped to success/completed |
| More pages / no more pages | Cursor and completeness are consistent |
| Too many rows / output cap | No skipped rows or sliced final text |
| Very long Unicode label | Valid UTF-8 and visible shortening |
| Literal Jinja syntax in data | Remains data, not evaluated |
| Newlines, controls and bidi characters | Cannot forge structural lines invisibly |
| Secret canaries in discarded metadata | Absent in text and public structured data |
| Missing template variable | Strict failure; no lenient default |
| Template fails after confirmed write | Receipt and no-replay semantics preserved |
| Unknown write + render failure | Remains unknown |
| Text-only MCP conversion | One text block and correct `isError` |

Boundary tests use `limit-1`, `limit`, `limit+1`, and byte expansion due to escaping. A renderer test is not a protocol test: separately run the exact MCP binary through discovery, a call, invalid arguments and EOF. Add determinism tests under multiple locale/timezone settings for presenters that display time/numbers.

**TEST-02 — SHOULD.** Property/fuzz tests ensure arbitrary bounded input never panics and never escapes a response budget. Benchmark typical and worst allowed views. Report bytes, rows, allocation/time observations and tokenizer-specific measurements only when actually collected.

The included reference tests exercise presentation paths; they do not certify real provider authorization, write idempotency, host behavior or the entire starter's protocol implementation.

## 15. Before/after example

External data:

```json
{
  "jobs": [
    {"id":"ag-17","status":"running","title":"Fix token refresh","provider":{"account":"private","access_token":"SECRET_CANARY"},"debug":{"attempt":3}},
    {"id":"ag-18","status":"failed","title":"Run integration tests","internal_latency_ms":183}
  ],
  "has_more": true,
  "next_cursor": "page-2",
  "request_headers": {"Authorization":"Bearer SECRET_CANARY"}
}
```

Projected reply:

```text
OK jobs: 2 returned; more=true
ag-17 | running | "Fix token refresh"
ag-18 | failed | "Run integration tests"
Cursor: page-2
```

This page read succeeded even though one listed job failed. Tool-call success is not the same fact as every object's success. Account data, headers, latency and provider debug structure are irrelevant to this call and never reach the template. The example does not prove that every title is safe to disclose; the product's authorization policy must establish that first.

## 16. Implementation map and adoption

The template reference lives in `scaffold/crates/mcp-presentation`: a pure local Rust crate, four embedded templates, typed projections, a bounded writer, read-page decoding and a status-preserving mutation receipt example. The starter's existing `get_status` and invalid-argument replies use the renderer. Job-page and mutation examples are library examples, not newly registered MCP tools and not new external effects.

The canonical document is `standard/MCP_RESPONSE_STANDARD.md`. Its exact export in `scaffold/docs/MCP_RESPONSE_STANDARD.md` contains no private inventory; CI compares the copies. Update the canonical file and export in the same PR.

Adopt this profile in existing products incrementally: inventory each tool's current result/consumer; define its compact view and essential fields; add representative fixtures; wire the renderer; check supported hosts; then remove raw-payload output. Do not change IDs, retry semantics, storage, workflow or tool names just to change formatting. Do not automatically migrate other repositories when editing the template.

Template/view changes are versioned with the product. Layout-only changes may be a patch if no downstream contract changes; lost identifiers, uncertainty, warnings, content fidelity or recovery capability require compatibility review even if the output schema did not change.

## 17. Review checklist

A reviewer should be able to answer: What happened? What effect is confirmed? Which object/request is involved? Is this complete/current? Can the agent continue without guessing? Did any secret/raw provider field leak? Can a formatting failure cause a duplicate write? Is the text shorter because noise was removed, not because necessary facts disappeared?

If one of these answers is unclear, a smaller byte count is not an improvement.

## 18. Primary sources and verification boundary

The numbered MUST/SHOULD rules and budgets are this family's design decisions. The following sources support library/protocol facts, not claims that this implementation passed tests:

- [MJ-FEATURES] MiniJinja 2.24.0 feature definitions: https://github.com/mitsuhiko/minijinja/blob/2.24.0/minijinja/Cargo.toml
- [MJ-ENV] MiniJinja environment configuration: https://github.com/mitsuhiko/minijinja/blob/2.24.0/minijinja/src/environment.rs
- [MJ-TEMPLATE] MiniJinja rendering APIs and deprecations: https://github.com/mitsuhiko/minijinja/blob/2.24.0/minijinja/src/template.rs
- [MCP] MCP 2026-07-28 tools, result schemas and error channels: https://modelcontextprotocol.io/specification/2026-07-28/server/tools
- [CARGO] Cargo workspace/dependency/lint inheritance: https://doc.rust-lang.org/cargo/reference/workspaces.html
- [CARGO] MSRV semantics: https://doc.rust-lang.org/cargo/reference/rust-version.html

Do not interpret these source references or a passing presentation test as release qualification. Record native compilation, black-box MCP checks and live integration evidence separately.
