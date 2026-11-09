//! Private Run-reader protocol for Pool terminal outcomes and namespace fences.
use crate::{
    config::Config,
    domain::Fault,
    managed_run::{RunError, RunPeer},
    managed_state::Route,
    store::Store,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Exact private request; never a participant command or owner observer grant.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    id: String,
    #[serde(flatten)]
    operation: Operation,
}
#[derive(Deserialize)]
#[serde(tag = "method", content = "params")]
enum Operation {
    #[serde(rename = "_managed_intent_outcome_v1")]
    Outcome(OutcomeParams),
    #[serde(rename = "_managed_namespace_seal_v1")]
    Seal(SealParams),
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OutcomeParams {
    version: u8,
    expected_store_id: String,
    intent_id: String,
    security_digest: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SealParams {
    version: u8,
    expected_store_id: String,
    request_id: String,
    bridge_route: Route,
    producer: String,
    issuer_epoch: String,
    retirement_key: String,
}
/// Bounded fixed error branch; no paths, proofs, payloads or credentials.
#[derive(Serialize)]
struct Error<'a> {
    version: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    store_id: Option<&'a str>,
    code: &'static str,
    recovery: &'static str,
}
fn opaque(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}
impl Request {
    /// Refuses this parsed request without reflecting payload or peer identity.
    pub fn refused(&self) -> Value {
        failure(&self.id, None, "peer_not_authorized", "none")
    }
    /// Validates request shape and returns no reflected unsafe value on failure.
    pub fn parse(value: Value) -> Result<Self, Fault> {
        let request: Self = serde_json::from_value(value).map_err(|_| Fault::Invalid)?;
        if !opaque(&request.id) {
            return Err(Fault::Invalid);
        }
        Ok(request)
    }
    /// Authenticates the kernel peer and its configured exact loaded executable before store access.
    pub fn authenticate(&self, config: &Config, pid: u32) -> Result<(), Fault> {
        let reader = config
            .managed_run_reader
            .as_ref()
            .ok_or(Fault::Unauthorized)?;
        let peer = RunPeer {
            socket: config.socket_path.clone(),
            expected_uid: config.expected_uid,
            executable: reader.executable.clone(),
            sha256: reader.sha256.clone(),
            route: Route {
                component_store_id: String::new(),
                route_id: String::new(),
                worker_uid: config.expected_uid,
            },
            pool_route: Route {
                component_store_id: String::new(),
                route_id: String::new(),
                worker_uid: config.expected_uid,
            },
            bridge_route: Route {
                component_store_id: String::new(),
                route_id: String::new(),
                worker_uid: config.expected_uid,
            },
            producer: String::new(),
            recovery_capabilities: Vec::new(),
        };
        crate::managed_run::verify_peer(pid, &peer).map_err(|_: RunError| Fault::Unauthorized)
    }
    /// Dispatches after peer authentication; the selected Store owns all SQL serialization.
    pub fn execute(&self, config: &Config, store: &mut Store) -> Value {
        let store_id = match store.managed_store_id() {
            Ok(id) => id,
            Err(_) => return failure(&self.id, None, "recovery_required", "operator"),
        };
        let result: Result<Value, (&'static str, &'static str)> = match &self.operation {
            Operation::Outcome(params) => {
                if params.version != 1 {
                    Err(("unsupported_version", "none"))
                } else if params.expected_store_id != store_id {
                    Err(("recovery_required", "operator"))
                } else if !opaque(&params.intent_id)
                    || params.security_digest.len() != 64
                    || !params
                        .security_digest
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    Err(("invalid", "none"))
                } else {
                    let grant = config
                        .managed_run_reader
                        .as_ref()
                        .ok_or(("peer_not_authorized", "none"));
                    grant.and_then(|grant| {
                        let route = Route {
                            component_store_id: grant.run_store_id.clone(),
                            route_id: grant.run_route_id.clone(),
                            worker_uid: config.expected_uid,
                        };
                        store
                            .managed_outcome(&params.intent_id, &params.security_digest, &route)
                            .and_then(|v| serde_json::to_value(v).map_err(|_| Fault::Internal))
                            .map_err(map_fault)
                    })
                }
            }
            Operation::Seal(params) => {
                let grant = config.managed_run_reader.as_ref();
                if params.version != 1 {
                    Err(("unsupported_version", "none"))
                } else if params.expected_store_id != store_id {
                    Err(("recovery_required", "operator"))
                } else if grant.is_none_or(|grant| {
                    grant.bridge_store_id != params.bridge_route.component_store_id
                        || grant.bridge_route_id != params.bridge_route.route_id
                        || grant.producer != params.producer
                        || params.bridge_route.worker_uid != config.expected_uid
                }) {
                    Err(("route_mismatch", "none"))
                } else if !opaque(&params.request_id)
                    || !opaque(&params.issuer_epoch)
                    || !opaque(&params.retirement_key)
                {
                    Err(("invalid", "none"))
                } else {
                    store.managed_seal(&params.bridge_route,&params.producer,&params.issuer_epoch,&params.request_id,&params.retirement_key).map(|seal|json!({"version":1,"store_id":store_id,"request_id":params.request_id,"seal_id":seal.seal_id,"bridge_route":params.bridge_route,"producer":params.producer,"issuer_epoch":params.issuer_epoch,"retirement_key":params.retirement_key,"state":if seal.sealed {"sealed"} else {"draining"}})).map_err(map_fault)
                }
            }
        };
        match result {
            Ok(value) => json!({"id":self.id,"result":value}),
            Err((code, recovery)) => failure(&self.id, Some(&store_id), code, recovery),
        }
    }
}
fn map_fault(fault: Fault) -> (&'static str, &'static str) {
    match fault {
        Fault::Conflict => ("intent_conflict", "none"),
        Fault::Invalid => ("invalid", "none"),
        Fault::Stale => ("binding_stale", "fresh_invocation"),
        Fault::Forbidden => ("route_mismatch", "none"),
        _ => ("recovery_required", "operator"),
    }
}
fn failure(id: &str, store_id: Option<&str>, code: &'static str, recovery: &'static str) -> Value {
    json!({"id":id,"error":Error{version:1,store_id,code,recovery}})
}
/// Content-free pre-store error for malformed or unauthorized requests.
pub(crate) fn refused() -> Value {
    failure("", None, "peer_not_authorized", "none")
}
