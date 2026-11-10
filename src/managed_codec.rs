//! Policy-independent canonical command codec for the managed-attempt protocol.
use crate::domain::{Command, Fault};
use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value, json};
use sha2::{Digest, Sha256};
use std::fmt;

const SECURITY_DOMAIN: &[u8] = b"agent-mcp/attempt-binding/security-command/v1\0";

/// Checks raw integer spellings before serde_json can convert an overflow to a float.
fn check_integer_tokens(input: &[u8]) -> Result<(), Fault> {
    let mut pos = 0;
    while pos < input.len() {
        match input[pos] {
            b'"' => {
                pos += 1;
                while pos < input.len() {
                    match input[pos] {
                        b'\\' => {
                            pos += 1;
                            if pos < input.len() {
                                pos += 1;
                            }
                        }
                        b'"' => {
                            pos += 1;
                            break;
                        }
                        _ => pos += 1,
                    }
                }
            }
            b'-' | b'0'..=b'9' => {
                let start = pos;
                pos += 1;
                while pos < input.len()
                    && matches!(input[pos], b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-')
                {
                    pos += 1;
                }
                let token = &input[start..pos];
                if !token.iter().any(|b| matches!(b, b'.' | b'e' | b'E')) {
                    let token = std::str::from_utf8(token).map_err(|_| Fault::Invalid)?;
                    if token.starts_with('-') {
                        token.parse::<i64>().map_err(|_| Fault::Invalid)?;
                    } else {
                        token.parse::<u64>().map_err(|_| Fault::Invalid)?;
                    }
                }
            }
            _ => pos += 1,
        }
    }
    Ok(())
}

/// A recursively parsed JSON value which rejects duplicate keys at every depth.
struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = Unique;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("unique-key JSON")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Unique, E> {
                Ok(Unique(Value::Bool(v)))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Unique, E> {
                Ok(Unique(Value::Number(v.into())))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Unique, E> {
                Ok(Unique(Value::Number(v.into())))
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Unique, E> {
                Number::from_f64(v)
                    .map(|n| Unique(Value::Number(n)))
                    .ok_or_else(|| E::custom("nonfinite"))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Unique, E> {
                Ok(Unique(Value::String(v.to_owned())))
            }
            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Unique, E> {
                Ok(Unique(Value::String(v)))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Unique, A::Error> {
                let mut result = Vec::new();
                while let Some(value) = seq.next_element::<Unique>()? {
                    result.push(value.0);
                }
                Ok(Unique(Value::Array(result)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Unique, A::Error> {
                let mut result = Map::new();
                while let Some((key, value)) = map.next_entry::<String, Unique>()? {
                    if result.insert(key, value.0).is_some() {
                        return Err(serde::de::Error::custom("duplicate key"));
                    }
                }
                Ok(Unique(Value::Object(result)))
            }
        }
        d.deserialize_any(UniqueVisitor)
    }
}

/// Parses a raw private protocol frame with lexical integer and duplicate-key checks.
pub(crate) fn parse_raw(input: &[u8]) -> Result<Value, Fault> {
    check_integer_tokens(input)?;
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let value = Unique::deserialize(&mut deserializer)
        .map_err(|_| Fault::Invalid)?
        .0;
    deserializer.end().map_err(|_| Fault::Invalid)?;
    Ok(value)
}

/// Strictly parses the already decoded MCP command without recovering lexical spelling.
pub(crate) fn normalize_command(input: Value) -> Result<(Command, Value), Fault> {
    let envelope = input.as_object().ok_or(Fault::Invalid)?;
    if envelope.len() != 2 || !envelope.contains_key("name") || !envelope.contains_key("arguments")
    {
        return Err(Fault::Invalid);
    }
    let name = envelope["name"].as_str().ok_or(Fault::Invalid)?;
    let args = envelope["arguments"].as_object().ok_or(Fault::Invalid)?;
    let extras: &[&str] = match name {
        "pool_create" => &["request_key", "name", "purpose", "acceptance"],
        "pool_list" => &["after"],
        "pool_get" => &[
            "pool_id",
            "after",
            "section",
            "proposal_id",
            "member_id",
            "wait_seconds",
            "reverse",
            "before",
            "field",
            "expected_revision",
        ],
        "pool_close" | "pool_join" => &[],
        "pool_update" => &["name", "purpose"],
        "pool_add" => &["address", "name", "role", "task"],
        "pool_start_agent" => &["name", "role", "task", "spec"],
        "pool_start_batch" => &["members"],
        "pool_replace" => &["member_id", "spec"],
        "pool_cancel_replacement" => &["operation_id"],
        "pool_member_update" => &["member_id", "name", "role", "task"],
        "pool_remove" | "pool_release_history" => &["member_id"],
        "pool_post" | "pool_notify_owner" => &["body"],
        "pool_send_member" => &["member_id", "body"],
        "pool_propose" => &["result", "criteria", "snapshot"],
        "pool_vote" => &["proposal_id", "roster_key", "choice", "evidence", "checks"],
        "pool_enrollment_get" => &["pool_id", "enrollment_id"],
        "pool_enrollment_resolve" => &[
            "pool_id",
            "enrollment_id",
            "expected_enrollment_revision",
            "request_key",
            "disposition",
        ],
        _ => return Err(Fault::Invalid),
    };
    let has_change = !matches!(
        name,
        "pool_create"
            | "pool_list"
            | "pool_get"
            | "pool_enrollment_get"
            | "pool_enrollment_resolve"
    );
    if args.keys().any(|key| {
        !extras.contains(&key.as_str())
            && !(has_change
                && ["pool_id", "expected_revision", "request_key"].contains(&key.as_str()))
    }) {
        return Err(Fault::Invalid);
    }
    let command: Command = serde_json::from_value(input).map_err(|_| Fault::Invalid)?;
    command.validate()?;
    let normalized = serde_json::to_value(&command).map_err(|_| Fault::Internal)?;
    Ok((command, normalized))
}

/// Recursively tags JSON values, preserving number categories and Unicode scalar key order.
fn tag(value: &Value) -> Result<Value, Fault> {
    Ok(match value {
        Value::Null => json!(["n"]),
        Value::Bool(v) => json!(["b", v]),
        Value::String(v) => json!(["s", v]),
        Value::Number(n) if n.is_i64() || n.is_u64() => json!(["i", n.to_string()]),
        Value::Number(n) => {
            let number = n.as_f64().filter(|v| v.is_finite()).ok_or(Fault::Invalid)?;
            json!([
                "f",
                format!("{:016x}", if number == 0.0 { 0 } else { number.to_bits() })
            ])
        }
        Value::Array(values) => {
            json!(["a", values.iter().map(tag).collect::<Result<Vec<_>, _>>()?])
        }
        Value::Object(values) => {
            let mut entries = values.iter().collect::<Vec<_>>();
            entries.sort_unstable_by_key(|(a, _)| *a);
            let pairs = entries
                .into_iter()
                .map(|(key, value)| Ok(json!([key, tag(value)?])))
                .collect::<Result<Vec<_>, Fault>>()?;
            json!(["o", pairs])
        }
    })
}

/// Computes the security digest over a normalized command and frozen context.
pub(crate) fn security_digest(command: &Value, context: &Value) -> Result<(usize, String), Fault> {
    digest(
        SECURITY_DOMAIN,
        &json!({"command":command,"context":context}),
    )
}

/// Hashes the versioned tagged encoding with a caller-supplied fixed domain.
pub(crate) fn digest(domain: &[u8], value: &Value) -> Result<(usize, String), Fault> {
    let canonical = serde_json::to_vec(&tag(value)?).map_err(|_| Fault::Internal)?;
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(&canonical);
    Ok((canonical.len(), format!("{:x}", digest.finalize())))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "Synthetic canonical codec fixtures")]
mod tests {
    use super::*;

    fn binding(member: &str, generation: u64) -> Value {
        json!({"pool_store_id":"s", "pool_id":"p", "member_id":member, "binding_generation":generation,
            "attempt":{"run_store_id":"rs","lineage_root_id":"e","execution_id":"e","sequence":1,"attempt_id":"a","launch_id":"00000000-0000-4000-8000-000000000001"},
            "actor":{"address":"host/codex/store/session","role":"root","native_id":"session","epoch":1},
            "run_route":{"component_store_id":"rs","route_id":"run-worker","worker_uid":1000},
            "bridge_route":{"component_store_id":"bs","route_id":"bridge-worker","worker_uid":1000}})
    }
    fn context(bindings: Vec<Value>) -> Value {
        json!({"version":1,"command_schema":"pool-command-v1","pool_store_id":"s","audience":"pool","producer":"frontend","intent_id":"intent1","invocation_key":"i","nonce":"n","bindings":bindings})
    }
    /// Pin all published canonical bytes and digests independently of domain validation.
    #[test]
    fn full_digest_schema_reference_vectors() {
        let ctx = context(vec![binding("m", 1)]);
        let cases = [
            (
                json!({"name":"pool_join","arguments":{"pool_id":"p","expected_revision":1,"request_key":"r"}}),
                ctx.clone(),
                1125,
                "db0cd9abfe4d65548071bd438ba304ab339af6fbdce425057f59c5f1996a8c67",
            ),
            (
                json!({"name":"pool_join","arguments":{"pool_id":"p","expected_revision":2,"request_key":"r"}}),
                ctx.clone(),
                1125,
                "cdae45c8644997f8a90e656568201c3ff2d19a1c42f407d0c26f4cdfc2cb983f",
            ),
            (
                json!({"name":"pool_vote","arguments":{"pool_id":"p","expected_revision":1,"request_key":"r","proposal_id":"proposal","roster_key":"roster","choice":"revoke","evidence":""}}),
                ctx.clone(),
                1236,
                "545ecbaa37c20c76c6146a2bc24e20ef06a909933e7ed518cf206345792ab48c",
            ),
            (
                json!({"name":"pool_propose","arguments":{"pool_id":"p","expected_revision":1,"request_key":"r","result":"done","criteria":"ok"}}),
                ctx.clone(),
                1176,
                "a0a5f7aa0c00319aa6f3a43dd136c0b0b1f5a8275c2db75c826e07fdb37283de",
            ),
            (
                json!({"name":"pool_create","arguments":{"request_key":"r","name":"n","purpose":"p"}}),
                ctx.clone(),
                1114,
                "5a5c4339498b65425cdbece2fb5438c38ee0713dbd3cecbe819d5d75924f349e",
            ),
            (
                json!({"name":"pool_create","arguments":{"request_key":"r","name":"n","purpose":"p","acceptance":[]}}),
                ctx.clone(),
                1138,
                "f14d23d558dcd50112474e253f293d9b4162409d3ba737f7e5d720073cc6074f",
            ),
            (
                json!({"name":"pool_start_agent","arguments":{"pool_id":"p","expected_revision":1,"request_key":"r","name":"n","role":"r","task":"t","spec":{"nested":[null,true,{"integer":1,"fraction":1.0}],"tag-object":{"$binary64":"3ff0000000000000"}}}}),
                ctx.clone(),
                1372,
                "fa4d7cf973ffabc17c364085925175f21343d94903940b916819b6fc2822ade5",
            ),
            (
                json!({"name":"pool_post","arguments":{"pool_id":"p","expected_revision":1,"request_key":"r","body":"É/猫\n\t\u{8}\u{c}\r\u{1}\"\\"}}),
                ctx.clone(),
                1169,
                "fb8966f9999933fa757185ce9964a6832860200cce4e011f332618dfd22f37ca",
            ),
            (
                json!({"name":"pool_join","arguments":{"pool_id":"p","expected_revision":1,"request_key":"r"}}),
                context(vec![binding("m", 1), binding("n", 2)]),
                1825,
                "55fb0766561a87ab60b5f38cc3c1f932e2021d91d3989c7183bb620ef4d949c3",
            ),
            (
                json!({"name":"pool_get","arguments":{"pool_id":"p","after":0,"section":"history","proposal_id":null,"member_id":null,"wait_seconds":0.125}}),
                ctx,
                1198,
                "2e6b2cc9c70c684a3a3ed15f65680e834ee9f22f2c6ad0b0ad13cd5326a3f961",
            ),
        ];
        for (command, context, length, expected) in cases {
            assert_eq!(
                security_digest(&command, &context).unwrap(),
                (length, expected.to_owned())
            );
        }
    }
    #[test]
    fn numeric_lexical_overflow() {
        for invalid in [
            "18446744073709551616",
            "-9223372036854775809",
            "{\"spec\":[18446744073709551616]}",
            "1e999",
            "{\"x\":1,\"x\":2}",
            "{\"x\":{\"a\":1,\"a\":2}}",
        ] {
            assert!(parse_raw(invalid.as_bytes()).is_err(), "{invalid}");
        }
        for valid in [
            "-9223372036854775808",
            "18446744073709551615",
            "18446744073709551616.0",
            "{\"integer\":\"18446744073709551616\"}",
        ] {
            assert!(parse_raw(valid.as_bytes()).is_ok(), "{valid}");
        }
        assert_eq!(tag(&json!(-0.0)).unwrap(), tag(&json!(0.0)).unwrap());
        assert_ne!(tag(&json!(1)).unwrap(), tag(&json!(1.0)).unwrap());
        assert_eq!(
            tag(&parse_raw(b"18446744073709551616.0").unwrap()).unwrap(),
            tag(&json!(18446744073709551616.0)).unwrap()
        );
    }
    #[test]
    fn normalized_command_rejects_unknown_flattened_fields_and_keeps_defaults() {
        let (_,join) = normalize_command(json!({"name":"pool_join","arguments":{"pool_id":"p","expected_revision":1,"request_key":"r"}})).unwrap();
        assert_eq!(
            join,
            json!({"name":"pool_join","arguments":{"pool_id":"p","expected_revision":1,"request_key":"r"}})
        );
        assert!(normalize_command(json!({"name":"pool_join","arguments":{"pool_id":"p","expected_revision":1,"request_key":"r","extra":true}})).is_err());
        let (_, get) = normalize_command(
            json!({"name":"pool_get","arguments":{"pool_id":"p","wait_seconds":-0.0}}),
        )
        .unwrap();
        assert_eq!(
            get,
            json!({"name":"pool_get","arguments":{"pool_id":"p","after":0,"section":"overview","proposal_id":null,"member_id":null}})
        );
        assert!(normalize_command(json!({"name":"pool_vote","arguments":{"pool_id":"p","expected_revision":1,"request_key":"r","proposal_id":"p","roster_key":"r","choice":"revoke","checks":null}})).is_err());
    }
    /// Every public variant uses the same typed normalization and rejects extra fields.
    #[test]
    fn full_digest_schema_all_command_variants() {
        let common = json!({"pool_id":"p","expected_revision":1,"request_key":"r"});
        let cases = [
            (
                "pool_create",
                json!({"request_key":"r","name":"name","purpose":"goal"}),
            ),
            ("pool_list", json!({})),
            ("pool_get", json!({"pool_id":"p"})),
            ("pool_update", json!({"name":"name","purpose":"goal"})),
            ("pool_close", json!({})),
            (
                "pool_add",
                json!({"address":"address","name":"name","role":"role","task":"task"}),
            ),
            (
                "pool_start_agent",
                json!({"name":"name","role":"role","task":"task","spec":{"value":[1,1.0]}}),
            ),
            (
                "pool_start_batch",
                json!({"members":[{"name":"name","role":"role","task":"task","spec":{}}]}),
            ),
            ("pool_replace", json!({"member_id":"member","spec":null})),
            (
                "pool_cancel_replacement",
                json!({"operation_id":"operation"}),
            ),
            (
                "pool_member_update",
                json!({"member_id":"member","name":"name","role":"role","task":"task"}),
            ),
            ("pool_remove", json!({"member_id":"member"})),
            ("pool_release_history", json!({"member_id":"member"})),
            ("pool_join", json!({})),
            ("pool_post", json!({"body":"message"})),
            (
                "pool_send_member",
                json!({"member_id":"member","body":"message"}),
            ),
            ("pool_notify_owner", json!({"body":"message"})),
            (
                "pool_propose",
                json!({"result":"result","criteria":"criteria","snapshot":null}),
            ),
            (
                "pool_vote",
                json!({"proposal_id":"proposal","roster_key":"roster","choice":"revoke","checks":[]}),
            ),
        ];
        for (name, mut args) in cases {
            if !matches!(name, "pool_create" | "pool_list" | "pool_get") {
                args.as_object_mut()
                    .unwrap()
                    .extend(common.as_object().unwrap().clone());
            }
            let input = json!({"name":name,"arguments":args});
            let (_, normalized) = normalize_command(input.clone()).unwrap();
            let (_, repeated) = normalize_command(normalized.clone()).unwrap();
            assert_eq!(normalized, repeated, "{name}");
            let mut invalid = input;
            invalid["arguments"]["unexpected"] = json!(true);
            assert!(normalize_command(invalid).is_err(), "{name}");
        }
    }
    /// rmcp has already parsed MCP JSON into a Value; the resident hashes that same Value.
    #[test]
    fn mcp_duplicate_keys_use_the_already_parsed_value() {
        #[derive(serde::Deserialize)]
        struct RpcCall {
            params: rmcp::model::CallToolRequestParams,
        }
        let raw=br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"pool_join","arguments":{"pool_id":"discarded","pool_id":"p","expected_revision":1,"request_key":"r"}}}"#;
        let call: RpcCall = serde_json::from_slice(raw).unwrap();
        let frontend = json!({"name":call.params.name,"arguments":call.params.arguments.unwrap()});
        assert_eq!(frontend["arguments"]["pool_id"], "p");
        let (_, normalized) = normalize_command(frontend).unwrap();
        let forwarded = serde_json::to_vec(&normalized).unwrap();
        let (_, resident) = normalize_command(parse_raw(&forwarded).unwrap()).unwrap();
        let context = context(vec![binding("m", 1)]);
        assert_eq!(
            security_digest(&normalized, &context).unwrap(),
            security_digest(&resident, &context).unwrap()
        );
        assert!(parse_raw(raw).is_err());
    }
}
