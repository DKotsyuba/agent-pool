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
            "Create a persistent pool and permanently become its external leader. Optional acceptance enables structured checks; an empty list uses the default goal criterion. Retry only the same request_key and intent.",
            object(
                json!({"request_key":string(128),"name":string(80),"purpose":string(8192),"acceptance":{"type":"array","maxItems":10,"items":object(json!({"id":string(32),"text":string(1024)}), &["id","text"])}}),
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
            "Read one bounded authenticated section. Forward history may wait up to 25 seconds; reverse history uses next_before. Content pages require field=purpose|snapshot and the prior expected_revision on continuation. Structured ballot checks follow vote_event_id in history. proposal_id selects a retained decision; owner-only binding requires member_id.",
            object(
                json!({"pool_id":string(128),"after":{"type":"integer","minimum":0},"section":{"type":"string","enum":["overview","members","history","proposal","votes","criteria","content","deliveries","binding"]},"proposal_id":string(128),"member_id":string(128),"wait_seconds":{"type":"number","minimum":0,"maximum":25},"reverse":{"type":"boolean"},"before":{"type":"string","pattern":"^[1-9][0-9]*$","maxLength":19},"field":{"type":"string","enum":["purpose","snapshot"]},"expected_revision":{"type":"integer","minimum":1}}),
                &["pool_id"],
            ),
            true,
        ),
        tool(
            "pool_update",
            "Owner updates pool name and purpose at the current revision; current members are notified.",
            mutation(
                json!({"name":string(80),"purpose":string(8192)}),
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
            "Owner reserves a pending member and requests one Run agent with retained history. With P3 enrollment enabled, spec.profile must equal the configured managed role; the receipt's created_id is the enrollment ID (read it with pool_enrollment_get). The member joins only after a qualified Run attestation and its own verified pool_join; lost responses never authorize a new start.",
            mutation(start.clone(), &["name", "role", "task", "spec"]),
            false,
        ),
        tool(
            "pool_start_batch",
            "Reserve an ordered group of 1-20 and request atomic Run admission with durable history pins. The receipt confirms the Pool intent only; with P3 enrollment enabled its created_id is the enrollment ID and qualification/join progress per member. Each member activates only through its own verified pool_join.",
            mutation(
                json!({"members":{"type":"array","minItems":1,"maxItems":20,"items":object(start, &["name","role","task","spec"])}}),
                &["members"],
            ),
            false,
        ),
        tool(
            "pool_replace",
            "Request replacement of a Run-managed member after its latest lineage is terminal and fully cleaned. A new lineage and new member ID are admitted on that exact precondition; the old member stays current until the qualified candidate is switched in one transaction. An unknown outcome keeps the roster frozen. Omit spec to reuse the original start.",
            mutation(
                json!({"member_id":string(128),"spec":{"type":["object","null"],"description":"Optional ordinary Run start specification, at most 64 KiB."}}),
                &["member_id"],
            ),
            false,
        ),
        tool(
            "pool_cancel_replacement",
            "Cancel an exact replacement only before any Run admission may have been submitted. Once submission is possible, preserve the intent and reconcile its original receipt.",
            mutation(json!({"operation_id":string(128)}), &["operation_id"]),
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
            "pool_release_history",
            "After closing a pool, record an explicit intent to release one member's retained Run history. Release is not executed until Run can prove its persistent store identity; once executed it permits pruning and cannot be undone.",
            mutation(json!({"member_id":string(128)}), &["member_id"]),
            false,
        ),
        tool(
            "pool_enrollment_get",
            "Owner reads one managed enrollment: per-member admission, qualification, binding, join state and recovery reason. Read-only; never starts or retries.",
            object(
                json!({"pool_id":string(128),"enrollment_id":string(128)}),
                &["pool_id", "enrollment_id"],
            ),
            true,
        ),
        tool(
            "pool_enrollment_resolve",
            "Owner closes a definitively admitted but unbound enrollment as retain_unassigned. Keeps the Run roots and pins, cancels no process, fences the pending memberships and restores the old member's slot for a failed replacement.",
            object(
                json!({"pool_id":string(128),"enrollment_id":string(128),"expected_enrollment_revision":{"type":"integer","minimum":1},"request_key":string(128),"disposition":{"type":"string","enum":["retain_unassigned"]}}),
                &[
                    "pool_id",
                    "enrollment_id",
                    "expected_enrollment_revision",
                    "request_key",
                    "disposition",
                ],
            ),
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
            "Post to current members, excluding the sender's duplicate wakeup. Leader is not automatically notified. Bodies over 2048 bytes are committed as ordered history parts; notifications show the first part.",
            mutation(json!({"body":string(8192)}), &["body"]),
            false,
        ),
        tool(
            "pool_send_member",
            "Deliver to one exact current membership ID and record shared history. Bodies over 2048 bytes are committed as ordered history parts; notifications show the first part. Removed IDs are never redirected.",
            mutation(
                json!({"member_id":string(128),"body":string(8192)}),
                &["member_id", "body"],
            ),
            false,
        ),
        tool(
            "pool_notify_owner",
            "Confirmed member explicitly notifies the hidden external owner. Bodies over 2048 bytes are committed as ordered history parts; notifications show the first part.",
            mutation(json!({"body":string(8192)}), &["body"]),
            false,
        ),
        tool(
            "pool_propose",
            "Owner or confirmed member opens a proposal with result, criteria, optional full snapshot and a frozen confirmed roster. Revising an open proposal archives it as stale. Accepted decisions remain immutable; leader never votes.",
            mutation(
                json!({"result":string(2048),"criteria":string(2048),"snapshot":string(65536)}),
                &["result", "criteria"],
            ),
            false,
        ),
        tool(
            "pool_vote",
            "Confirmed members vote against exact proposal_id and roster_key. Structured ready requires a check for every acceptance criterion; an unmet check is recorded but prevents agreement. Other pools require ready/block evidence. Acceptance never closes the pool or stops agents.",
            mutation(
                json!({"proposal_id":string(128),"roster_key":string(128),"choice":{"type":"string","enum":["ready","block","revoke"]},"evidence":{"type":"string","maxLength":2048},"checks":{"type":"array","maxItems":10,"items":object(json!({"criterion_id":string(32),"status":{"type":"string","enum":["met","unmet"]},"evidence":string(1024)}), &["criterion_id","status","evidence"])}}),
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
        (
            "pool_pending",
            "PENDING pool {{ pool_id }} request {{ request_key }}. Retry the identical request key with fresh proof.\n",
        ),
        ("pool_list", include_str!("../templates/pool_list.j2")),
        ("pool_private", include_str!("../templates/pool_private.j2")),
        (
            "pool_enrollment",
            include_str!("../templates/pool_enrollment.j2"),
        ),
    ]
}
/// Release-blocking unimplemented tools. P3 single start, batch and
/// replacement were removed individually after their named end-to-end rows
/// (p3_single_enrollment, p3_batch_enrollment, p3_replace_end_to_end) passed;
/// installed-provider qualification remains a separate release gate.
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
#[derive(Serialize)]
struct PendingView<'a> {
    pool_id: &'a str,
    request_key: &'a str,
}
/// Renders typed immutable outcomes; failures preserve committed identity and exact-retry semantics.
pub fn present(reply: Result<Reply, Fault>, templates: &Templates) -> CallToolResult {
    let error = reply.is_err();
    let rendered=match &reply{
        Ok(Reply::View(v))=>templates.render("pool_view",v),
        Ok(Reply::OwnerView{view,bindings})=>templates.render("pool_view",view).and_then(|mut text|{text.push_str(&templates.render("pool_private",&PrivateView{bindings})?);if text.len()>16384{Err("presentation_failed")}else{Ok(text)}}),
        Ok(Reply::Receipt(r))=>templates.render("pool_receipt",r),
        Ok(Reply::Pending{pool_id,request_key})=>templates.render("pool_pending",&PendingView{pool_id,request_key}),
        Ok(Reply::List{pools,next_after,has_more})=>templates.render("pool_list",&ListView{pools,next_after,has_more:*has_more}),
        Ok(Reply::Enrollment(view))=>templates.render("pool_enrollment",view),
        Err(code)=>templates.render("pool_error",&ErrorView{code:if *code==Fault::Completed{Fault::Closed}else{*code},recovery:match code{
            Fault::Stale=>"Read pool_get for current revision and proposal/roster identity before a new intent.",
            Fault::Unavailable=>"A previous write may have committed. Inspect pool_get or repeat only the identical request_key and intent.",
            Fault::RelaunchRequired=>"Relaunch the Pool resident after Bridge managed mode is enabled. Preserve the original request_key for recovery.",
            Fault::Unauthorized=>"Fresh native identity is required; no pool command was authorized.",
            Fault::Forbidden=>"The current authenticated caller cannot perform this action.",
            Fault::Conflict=>"A role, membership or idempotency conflict prevents this intent.",
            Fault::Closed=>"This pool was explicitly closed; global leader status remains.",
            Fault::Completed=>"This pool is completed: a formal completion record is committed and final (it was not explicitly closed). Reads, messages, explicit close and history release remain.",
            Fault::Invalid=>"Check documented fields, UTF-8 byte limits and exact identifiers.",
            Fault::Internal=>"No success is confirmed. Inspect state before repeating the same intent.",
        }}),
    };
    let text=rendered.unwrap_or_else(|_|match reply{
        Ok(Reply::Receipt(r))=>format!("COMMITTED pool {} revision={} event={}; presentation degraded. Use pool_get; do not create a new request_key.",r.pool_id,r.revision,r.event.event_id),
        Ok(Reply::Pending{pool_id,request_key})=>format!("PENDING pool {pool_id} request {request_key}; presentation degraded. Retry the identical key with fresh proof."),
        Ok(Reply::View(v))|Ok(Reply::OwnerView{view:v,..})=>format!("READ COMPLETED pool {} revision={}; presentation degraded, content omitted. Retry the same section and cursor; no mutation occurred.",v.pool.pool_id,v.pool.revision),
        Ok(Reply::List{..})=>"READ COMPLETED; presentation degraded, content omitted. Retry the same list cursor.".into(),
        Ok(Reply::Enrollment(view))=>format!("READ COMPLETED enrollment {} state={} revision={}; presentation degraded. Retry the same read; no Run call or retry was made.",view.enrollment_id,view.state,view.revision),
        Err(Fault::RelaunchRequired)=>"ERROR relaunch_required; relaunch the Pool resident after Bridge managed mode is enabled. Preserve the original request_key for recovery.".into(),
        Err(Fault::Completed)=>"ERROR closed; the pool is completed (formal completion record committed), not explicitly closed. No mutation was applied.".into(),
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
        assert_eq!(defs.len(), 22);
        assert!(incomplete().is_empty());
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
            created_ids: Vec::new(),
            event: Event {
                event_id: 7,
                event_id_exact: None,
                revision: 9,
                kind: "message".into(),
                author: Author::Member("member".into()),
                body: format!("{{{{literal}}}}\n{}", "\\".repeat(4096)),
                recipient: None,
                check: None,
                vote_event_id: None,
                message_event_id: None,
                part_index: None,
                part_count: None,
            },
            status: "committed; delivery pending".into(),
        };
        let normal =
            serde_json::to_string(&present(Ok(Reply::Receipt(Box::new(r.clone()))), &t)).unwrap();
        assert!(normal.contains("{{literal}}"));
        assert!(!normal.contains("presentation degraded"));
        let mut replacement = r.clone();
        replacement.event.kind = "replacement_requested".into();
        replacement.created_ids.push("candidate-member".into());
        let rendered =
            serde_json::to_string(&present(Ok(Reply::Receipt(Box::new(replacement))), &t)).unwrap();
        assert!(rendered.contains(
            "Candidate replacement member (not current until admission): candidate-member"
        ));
        assert!(!rendered.contains("Created members in request order"));
        let broken = Templates::new(&[("pool_receipt", "{{ missing }}")]).unwrap();
        let fallback =
            serde_json::to_string(&present(Ok(Reply::Receipt(Box::new(r))), &broken)).unwrap();
        assert!(fallback.contains("COMMITTED pool pool-id revision=9 event=7"));
        assert!(fallback.contains("do not create a new request_key"));
    }

    /// A completed pool keeps the `closed` code but never claims an explicit close.
    #[test]
    fn completed_refusal_is_distinct_from_explicit_close() {
        let normal = Templates::new(&templates()).unwrap();
        let broken = Templates::new(&[("pool_error", "{{ missing }}")]).unwrap();
        let completed = serde_json::to_string(&present(Err(Fault::Completed), &normal)).unwrap();
        assert!(completed.contains("ERROR closed."));
        assert!(completed.contains("formal completion record"));
        assert!(!completed.contains("explicitly closed;"));
        let closed = serde_json::to_string(&present(Err(Fault::Closed), &normal)).unwrap();
        assert!(closed.contains("explicitly closed; global leader status remains"));
        let degraded = serde_json::to_string(&present(Err(Fault::Completed), &broken)).unwrap();
        assert!(degraded.contains("ERROR closed; the pool is completed"));
    }

    /// The owner enrollment projection renders per-job facts and degrades safely.
    #[test]
    fn enrollment_view_renders_and_degrades() {
        use crate::domain::{EnrollmentJobView, EnrollmentView};
        let view = EnrollmentView {
            pool_id: "pool".into(),
            enrollment_id: "enrollment".into(),
            mode: "start".into(),
            revision: 3,
            state: "admitted".into(),
            attention: None,
            replaces: None,
            jobs: vec![EnrollmentJobView {
                index: 0,
                member_id: "member".into(),
                state: "bound_pending_join".into(),
                lineage_root_id: Some("ag-root".into()),
                pin_id: Some("pin".into()),
                binding_generation: Some(1),
                attention: Some("qualification_pending".into()),
            }],
        };
        let t = Templates::new(&templates()).unwrap();
        let text =
            serde_json::to_string(&present(Ok(Reply::Enrollment(Box::new(view.clone()))), &t))
                .unwrap();
        assert!(
            text.contains("ENROLLMENT enrollment pool pool mode=start state=admitted revision=3")
        );
        assert!(text.contains("member=member state=bound_pending_join root=ag-root pin=pin generation=1 attention=qualification_pending"));
        let broken = Templates::new(&[("pool_enrollment", "{{ missing }}")]).unwrap();
        let degraded =
            serde_json::to_string(&present(Ok(Reply::Enrollment(Box::new(view))), &broken))
                .unwrap();
        assert!(
            degraded.contains("READ COMPLETED enrollment enrollment state=admitted revision=3")
        );
    }

    #[test]
    fn pending_keeps_exact_replay_key_even_when_rendering_fails() {
        let broken = Templates::new(&[("pool_pending", "{{ missing }}")]).unwrap();
        let result = present(
            Ok(Reply::Pending {
                pool_id: "pool-1".into(),
                request_key: "request-1".into(),
            }),
            &broken,
        );
        let value = serde_json::to_string(&result).unwrap();
        assert!(value.contains("PENDING pool pool-1 request request-1"));
        assert_eq!(result.is_error, Some(false));
    }

    #[test]
    fn relaunch_required_reports_recovery_even_when_rendering_fails() {
        let normal = Templates::new(&templates()).unwrap();
        let broken = Templates::new(&[("pool_error", "{{ missing }}")]).unwrap();
        for templates in [&normal, &broken] {
            let result = present(Err(Fault::RelaunchRequired), templates);
            let value = serde_json::to_string(&result).unwrap();
            assert!(value.contains("relaunch_required"));
            assert!(
                value.contains("Relaunch the Pool resident")
                    || value.contains("relaunch the Pool resident")
            );
            assert!(value.contains("original request_key"));
            assert_eq!(result.is_error, Some(true));
        }
    }
}
