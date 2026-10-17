//! Explicit MCP tool schemas and typed, bounded MiniJinja result presentation.
use crate::{
    domain::{Fault, Reply},
    response::Templates,
};
use mcp_presentation::Renderer;
use rmcp::model::{CallToolResult, ContentBlock};
use serde::Serialize;
use serde_json::{Value, json};

/// Constructs one closed flat input schema with every required field declared explicitly.
fn object(fields: Value, required: &[&str]) -> Value {
    json!({"type":"object","properties":fields,"required":required,"additionalProperties":false})
}
/// Describes text bounds; Rust additionally enforces UTF-8 byte limits and control exclusions.
fn string(max: usize) -> Value {
    json!({"type":"string","minLength":1,"maxLength":max})
}
/// Extends common write preconditions with explicit flat tool fields; identity is never an argument.
fn mutation(fields: Value, required: &[&str]) -> Value {
    let mut base = json!({"pool_id":string(128),"expected_revision":{"type":"integer","minimum":1},"request_key":string(128)});
    if let (Some(base), Some(extra)) = (base.as_object_mut(), fields.as_object()) {
        base.extend(extra.clone());
    }
    let mut all = vec!["pool_id", "expected_revision", "request_key"];
    all.extend_from_slice(required);
    object(base, &all)
}
/// Builds one registry entry with explicit effect and replay hints.
fn tool(name: &str, description: &str, schema: Value, read: bool) -> Value {
    json!({"name":name,"description":description,"inputSchema":schema,"annotations":{"readOnlyHint":read,"destructiveHint":!read,"idempotentHint":true,"openWorldHint":!read}})
}
/// Exports all tools without credentials; each actual Pool execution authenticates in the resident.
pub fn definitions() -> Vec<Value> {
    let role = json!({"name":string(80),"role":string(160),"task":string(512)});
    let mut add = role.clone();
    add["address"] = string(1024);
    let mut start = role.clone();
    start["spec"] = json!({"type":"object","description":"Original Run start specification, at most 64 KiB. Required tools are asserted, never injected."});
    let mut member = role;
    member["member_id"] = string(128);
    vec![
        tool(
            "get_status",
            "Report product identity and qualification. No service or credentials needed.",
            object(json!({}), &[]),
            true,
        ),
        tool(
            "pool_create",
            "Create a persistent pool and permanently become a global external leader. Current or pending members cannot create pools. Retry only the same request_key and intent.",
            object(
                json!({"request_key":string(128),"name":string(80),"purpose":string(512)}),
                &["request_key", "name", "purpose"],
            ),
            false,
        ),
        tool(
            "pool_list",
            "Read ten accessible pools per page; after is the last exact pool ID. Leader is excluded from all rosters.",
            object(json!({"after":string(128)}), &[]),
            true,
        ),
        tool(
            "pool_get",
            "Read one bounded authenticated section: overview/members up to five assignments (two with owner mappings), history up to three events within 10 KiB, votes up to three ballots. after resumes within that section. proposal_id reads a retained decision. Removed members cannot read.",
            object(
                json!({"pool_id":string(128),"after":{"type":"integer","minimum":0},"section":{"type":"string","enum":["overview","members","history","proposal","votes","deliveries"]},"proposal_id":string(128)}),
                &["pool_id"],
            ),
            true,
        ),
        tool(
            "pool_update",
            "Owner updates pool name and purpose at the current revision; current members are notified.",
            mutation(
                json!({"name":string(80),"purpose":string(512)}),
                &["name", "purpose"],
            ),
            false,
        ),
        tool(
            "pool_close",
            "Owner explicitly closes the pool and revokes memberships. Cancels only provably unhanded delivery; never stops processes or clears global leader status.",
            mutation(json!({}), &[]),
            false,
        ),
        tool(
            "pool_add",
            "Owner invites one canonical Bridge address and delivers onboarding. Leaders and reserved agents refuse. Maximum 20 current/pending members; actual identity binds through pool_join.",
            mutation(add, &["address", "name", "role", "task"]),
            false,
        ),
        tool(
            "pool_start_agent",
            "Owner reserves a pending member and durably requests one Run agent with onboarding and required MCP assertions. Lost responses never authorize a replacement agent.",
            mutation(start, &["name", "role", "task", "spec"]),
            false,
        ),
        tool(
            "pool_member_update",
            "Owner changes an exact current member assignment, notifies members and stales unfinished proposals. Accepted decisions stay immutable.",
            mutation(member, &["member_id", "name", "role", "task"]),
            false,
        ),
        tool(
            "pool_remove",
            "Owner removes a member; members may remove only themselves. Revokes access, retires unhanded deliveries and sends one final notice. Does not stop execution.",
            mutation(json!({"member_id":string(128)}), &["member_id"]),
            false,
        ),
        tool(
            "pool_join",
            "Pending agent acknowledges the current onboarding revision under fresh native identity. Leaders cannot join any pool. Delivery is not acknowledgment.",
            mutation(json!({}), &[]),
            false,
        ),
        tool(
            "pool_post",
            "Post to current members, excluding the sender's duplicate wakeup. Leader is not automatically notified. Recorded in shared history.",
            mutation(json!({"body":string(2048)}), &["body"]),
            false,
        ),
        tool(
            "pool_send_member",
            "Deliver to one exact current membership ID and record shared history. No external or cross-pool destination. Removed IDs are never redirected.",
            mutation(
                json!({"member_id":string(128),"body":string(2048)}),
                &["member_id", "body"],
            ),
            false,
        ),
        tool(
            "pool_notify_owner",
            "Confirmed member explicitly notifies the hidden external owner, without an address argument. Recorded in shared history.",
            mutation(json!({"body":string(2048)}), &["body"]),
            false,
        ),
        tool(
            "pool_propose",
            "Owner or confirmed member opens one proposal with result, criteria and a frozen confirmed roster. A still-open proposal prevents another. Leader never votes.",
            mutation(
                json!({"result":string(2048),"criteria":string(2048)}),
                &["result", "criteria"],
            ),
            false,
        ),
        tool(
            "pool_vote",
            "Confirmed members vote against exact proposal_id and roster_key. Ready requires evidence; block/revoke persist. Unanimity accepts an immutable decision without closing the pool or stopping agents.",
            mutation(
                json!({"proposal_id":string(128),"roster_key":string(128),"choice":{"type":"string","enum":["ready","block","revoke"]},"evidence":{"type":"string","maxLength":2048}}),
                &["proposal_id", "roster_key", "choice"],
            ),
            false,
        ),
    ]
}
/// Closed embedded layouts are parsed at startup before admitting any mutation.
pub fn templates() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "invalid_arguments",
            "ERROR invalid_arguments: get_status accepts an empty argument object.\n",
        ),
        ("pool_error", "ERROR {{ code }}. {{ recovery }}\n"),
        ("pool_view", include_str!("../templates/pool_view.j2")),
        ("pool_receipt", include_str!("../templates/pool_receipt.j2")),
        ("pool_list", include_str!("../templates/pool_list.j2")),
        ("pool_private", include_str!("../templates/pool_private.j2")),
    ]
}
/// Reports actual source stubs; live release qualification remains independently unverified.
pub fn incomplete() -> Vec<&'static str> {
    Vec::new()
}
/// Handles credential-free identity only; Pool commands route through the authenticated resident.
pub async fn call(
    name: &str,
    args: Value,
    identity: &Renderer,
    templates: &Templates,
) -> Option<CallToolResult> {
    if name != "get_status" {
        return None;
    }
    if !args.as_object().is_some_and(|a| a.is_empty()) {
        return Some(result(
            templates
                .render("invalid_arguments", &())
                .unwrap_or_else(|_| {
                    "ERROR invalid_arguments; no effect. Presentation degraded.".into()
                }),
            true,
        ));
    }
    let reply = identity.identity(
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        crate::qualification(),
    );
    Some(result(reply.text().into(), reply.is_error()))
}
/// Closed failure projection; never contains a provider message, storage path or native address.
#[derive(Serialize)]
struct ErrorView {
    /// Safe domain class.
    code: Fault,
    /// Recovery selected from the immutable outcome.
    recovery: &'static str,
}
/// Constructed only after explicit owner authorization; absent from participant presentation.
#[derive(Serialize)]
struct PrivateView<'a> {
    /// Exact private mappings for the already displayed roster page.
    bindings: &'a [crate::domain::Binding],
}
/// Bounded list layout context.
#[derive(Serialize)]
struct ListView<'a> {
    /// Accessible metadata without proposal bodies.
    pools: &'a [crate::domain::Pool],
    /// Exclusive cursor of the last displayed pool.
    next_after: &'a Option<String>,
    /// Whether more accessible pools remain.
    has_more: bool,
}
/// Renders typed immutable outcomes; failures preserve committed identity and exact-retry semantics.
pub fn present(reply: Result<Reply, Fault>, templates: &Templates) -> CallToolResult {
    let error = reply.is_err();
    let rendered=match &reply{
        Ok(Reply::View(v))=>templates.render("pool_view",v),
        Ok(Reply::OwnerView{view,bindings})=>templates.render("pool_view",view).and_then(|mut text|{text.push_str(&templates.render("pool_private",&PrivateView{bindings})?);if text.len()>16384{Err("presentation_failed")}else{Ok(text)}}),
        Ok(Reply::Receipt(r))=>templates.render("pool_receipt",r),
        Ok(Reply::List{pools,next_after,has_more})=>templates.render("pool_list",&ListView{pools,next_after,has_more:*has_more}),
        Err(code)=>templates.render("pool_error",&ErrorView{code:*code,recovery:match code{
            Fault::Stale=>"Read pool_get for current revision and proposal/roster identity before a new intent.",
            Fault::Unavailable=>"A previous write may have committed. Inspect pool_get or repeat only the identical request_key and intent.",
            Fault::Unauthorized=>"Fresh native identity is required; no pool command was authorized.",
            Fault::Forbidden=>"The current authenticated caller cannot perform this action.",
            Fault::Conflict=>"A role, membership or idempotency conflict prevents this intent.",
            Fault::Closed=>"This pool was explicitly closed; global leader status remains.",
            Fault::Invalid=>"Check documented fields, UTF-8 byte limits and exact identifiers.",
            Fault::Internal=>"No success is confirmed. Inspect state before repeating the same intent.",
        }}),
    };
    let text=rendered.unwrap_or_else(|_|match reply{
        Ok(Reply::Receipt(r))=>format!("COMMITTED pool {} revision={} event={}; presentation degraded. Use pool_get; do not create a new request_key.",r.pool_id,r.revision,r.event.event_id),
        Ok(Reply::View(v))|Ok(Reply::OwnerView{view:v,..})=>format!("READ COMPLETED pool {} revision={}; presentation degraded, content omitted. Retry the same section and cursor; no mutation occurred.",v.pool.pool_id,v.pool.revision),
        Ok(Reply::List{..})=>"READ COMPLETED; presentation degraded, content omitted. Retry the same list cursor.".into(),
        Err(code)=>format!("ERROR {code}; presentation degraded. No success confirmed; preserve the original request_key for reconciliation."),
    });
    result(text, error)
}
/// Emits exactly one text block with execution isError independent of template success.
fn result(text: String, error: bool) -> CallToolResult {
    let mut out = CallToolResult::success(vec![ContentBlock::text(text)]);
    out.is_error = Some(error);
    out
}

/// Pure rendering checks use no credentials or live transports.
#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "Test fixtures")]
mod tests {
    use super::*;
    /// Every tool advertises a flat closed schema and explicit read effect.
    #[test]
    fn tool_catalog_is_closed() {
        let defs = definitions();
        assert_eq!(defs.len(), 16);
        for d in defs {
            assert_eq!(d["inputSchema"]["additionalProperties"], false);
            assert_eq!(d["inputSchema"]["type"], "object");
            assert!(d["annotations"]["readOnlyHint"].is_boolean());
        }
    }
    /// Literal templates remain data; presentation failure preserves an already committed receipt.
    #[test]
    fn quoted_receipt_and_failure_keep_outcome() {
        use crate::domain::*;
        let t = Templates::new(&templates()).unwrap();
        let r = Receipt {
            pool_id: "pool-id".into(),
            revision: 9,
            created_id: None,
            event: Event {
                event_id: 7,
                revision: 9,
                kind: "message".into(),
                author: Author::Member("member".into()),
                body: format!("{{{{literal}}}}\n{}", "\\".repeat(4096)),
                recipient: None,
            },
            status: "committed; delivery pending".into(),
        };
        let normal = serde_json::to_string(&present(Ok(Reply::Receipt(r.clone())), &t)).unwrap();
        assert!(normal.contains("{{literal}}"));
        assert!(!normal.contains("presentation degraded"));
        let broken = Templates::new(&[("pool_receipt", "{{ missing }}")]).unwrap();
        let fallback = serde_json::to_string(&present(Ok(Reply::Receipt(r)), &broken)).unwrap();
        assert!(fallback.contains("COMMITTED pool pool-id revision=9 event=7"));
        assert!(fallback.contains("do not create a new request_key"));
    }
}
