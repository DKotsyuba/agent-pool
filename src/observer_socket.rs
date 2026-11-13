//! Optional group-accessible, read-only observer endpoint of the resident.
//!
//! Authorization is the kernel-reported peer UID against the configured allowlist; there is
//! no credential. The request is the plain observer [`Request`] line (no `observer_credential`),
//! restricted to a closed set of Pool-state reads. Mutations, native commands, Run calls,
//! private mappings and owner diagnostics are not representable or are refused.
use crate::{
    config::{Config, ObserverSocket},
    domain::Fault,
    integrations::{self, EXCHANGE_TIMEOUT},
    observer::{self, Data, Envelope, Operation, Request},
    runtime::{SharedStore, SocketGuard, stored},
};
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::{
    fs,
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
};
use tokio::{
    io::AsyncWriteExt,
    net::{UnixListener, UnixStream},
    sync::{OwnedSemaphorePermit, Semaphore},
};

/// Concurrent observer connections, separate from the resident's own admission ceiling.
pub(crate) const MAX_CONNECTIONS: usize = 8;
/// Largest accepted request line; observer requests are small selectors.
pub(crate) const MAX_REQUEST: usize = 65_536;
/// Advertised on this endpoint's identity so a client can tell which route answered.
pub(crate) const CAPABILITY: &str = "observer_socket_v1";
/// Resident capabilities whose operations this endpoint never serves.
const WITHHELD: [&str; 2] = ["run_proof_v1", "managed_capacity_v1"];
/// `get` sections that only project retained Pool state.
const SECTIONS: [&str; 9] = [
    "overview",
    "members",
    "history",
    "proposal",
    "votes",
    "criteria",
    "content",
    "deliveries",
    "decisions",
];

/// Closed allowlist of reads. The match is exhaustive so a new operation is refused until
/// it is classified here; `get` admits only listed sections and never private bindings.
pub(crate) fn permitted(request: &Request) -> Result<(), Fault> {
    match &request.operation {
        Operation::Identity(_)
        | Operation::List(_)
        | Operation::InventorySnapshot(_)
        | Operation::CompletionGet(_)
        | Operation::EnrollmentGet(_) => Ok(()),
        Operation::Get(args)
            if !args.include_bindings && SECTIONS.contains(&args.section.as_str()) =>
        {
            Ok(())
        }
        Operation::Get(_) | Operation::ManagedCapacity(_) => Err(Fault::Unauthorized),
    }
}

/// Admits an allowlisted peer within the connection cap. Other peers get one refusal line
/// (`unauthorized`, or `unavailable` when full) without their input being read.
pub(crate) fn admit(
    stream: UnixStream,
    allowed: &[u32],
    permits: &Arc<Semaphore>,
) -> Option<(UnixStream, OwnedSemaphorePermit)> {
    if !admitted(&stream, allowed) {
        refuse(stream, Fault::Unauthorized);
        return None;
    }
    match Arc::clone(permits).try_acquire_owned() {
        Ok(permit) => Some((stream, permit)),
        Err(_) => {
            refuse(stream, Fault::Unavailable);
            None
        }
    }
}

/// True only when the kernel reports a peer UID on the allowlist.
fn admitted(stream: &UnixStream, allowed: &[u32]) -> bool {
    stream
        .peer_cred()
        .is_ok_and(|credentials| allowed.contains(&credentials.uid()))
}

/// Best-effort one-line refusal, then close, without reading input or spawning a task.
/// The nonblocking descriptor is written directly: a fresh tokio stream has no readiness yet.
fn refuse(stream: UnixStream, code: Fault) {
    use std::io::Write;
    if let (Ok(bytes), Ok(mut stream)) = (
        observer::encode(&Envelope::failure("error", code)),
        stream.into_std(),
    ) {
        let _ = stream.write(&bytes);
    }
}

/// Decodes, authorizes and answers one request; every failure is a typed error envelope.
pub(crate) async fn answer(bytes: &[u8], store: &SharedStore) -> Envelope {
    let request = serde_json::from_slice::<Request>(bytes);
    let kind = request.as_ref().map_or("error", Request::kind);
    let result = async {
        let request = request.map_err(|_| Fault::Invalid)?;
        request.validate()?;
        permitted(&request)?;
        let mut data = stored(store, move |store| store.observe(&request)).await?;
        if let Data::Identity(identity) = &mut data {
            identity
                .capabilities
                .retain(|capability| !WITHHELD.contains(&capability.as_str()));
            identity.capabilities.push(CAPABILITY.into());
        }
        Ok(data)
    }
    .await;
    match result {
        Ok(data) => Envelope::success(kind, data),
        Err(error) => Envelope::failure(kind, error),
    }
}

/// Serves one admitted connection: one bounded request line, one envelope line, then close.
pub(crate) async fn connection(mut stream: UnixStream, store: SharedStore) -> Result<(), Fault> {
    let read = tokio::time::timeout(
        EXCHANGE_TIMEOUT,
        integrations::read_frame_limited(&mut stream, MAX_REQUEST),
    )
    .await
    .map_err(|_| Fault::Unavailable)?;
    let envelope = match read {
        Ok(bytes) => answer(&bytes, &store).await,
        Err(Fault::Invalid) => Envelope::failure("error", Fault::Invalid),
        Err(error) => return Err(error),
    };
    let bytes = observer::encode(&envelope)
        .or_else(|error| observer::encode(&Envelope::failure(&envelope.kind, error)))?;
    tokio::time::timeout(EXCHANGE_TIMEOUT, stream.write_all(&bytes))
        .await
        .map_err(|_| Fault::Unavailable)?
        .map_err(|_| Fault::Unavailable)
}

/// Binds the configured endpoint with its group and mode, refusing a live or foreign entry.
/// The directory must already exist with the Run-directory policy for `expected_uid`; a stale
/// socket owned by `expected_uid` is removed only after connection refusal.
pub(crate) async fn listener(
    config: &Config,
    settings: &ObserverSocket,
) -> Result<(UnixListener, SocketGuard), Fault> {
    #[cfg(target_os = "linux")]
    {
        crate::config::identity_uid_map()?;
        let path = &settings.path;
        let directory = crate::config::observer_directory(path, config.expected_uid)?;
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                if !metadata.file_type().is_socket() || metadata.uid() != config.expected_uid {
                    return Err(Fault::Conflict);
                }
                match tokio::time::timeout(EXCHANGE_TIMEOUT, UnixStream::connect(path)).await {
                    Ok(Err(error)) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                        fs::remove_file(path).map_err(|_| Fault::Unavailable)?
                    }
                    _ => return Err(Fault::Conflict),
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => return Err(Fault::Unavailable),
        }
        let listener = UnixListener::bind(path).map_err(|_| Fault::Unavailable)?;
        let bound = fs::symlink_metadata(path).map_err(|_| Fault::Unavailable)?;
        let guard = SocketGuard {
            path: path.clone(),
            device: bound.dev(),
            inode: bound.ino(),
        };
        std::os::unix::fs::lchown(path, None, Some(settings.gid))
            .map_err(|_| Fault::Unavailable)?;
        fs::set_permissions(path, fs::Permissions::from_mode(settings.mode))
            .map_err(|_| Fault::Unavailable)?;
        let metadata = fs::symlink_metadata(path).map_err(|_| Fault::Unavailable)?;
        if !metadata.file_type().is_socket()
            || (metadata.dev(), metadata.ino()) != (guard.device, guard.inode)
            || metadata.uid() != config.expected_uid
            || metadata.gid() != settings.gid
            || metadata.mode() & 0o7777 != settings.mode
            || crate::config::observer_directory(path, config.expected_uid)? != directory
        {
            return Err(Fault::Unavailable);
        }
        Ok((listener, guard))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (config, settings);
        Err(Fault::Unavailable)
    }
}

/// Allowlist, closed read set, endpoint policy and DB immutability, without a live resident.
/// Linux only, like the endpoint itself.
#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::{
        domain::{Actor, Command, Reply},
        store::Store,
    };
    use serde_json::{Value, json};
    use std::{path::Path, sync::Mutex, time::Duration};
    use tokio::io::AsyncReadExt;

    /// Store holding one pool, plus its ID; nothing else is configured.
    fn store(path: &Path) -> Result<(SharedStore, String), Box<dyn std::error::Error>> {
        let mut initial = Store::open(&path.join("pool.db"))?;
        let actor = Actor::verified("codex:test:observer-socket:owner".into(), "owner", "root")?;
        let Reply::Receipt(receipt) = initial.execute(
            &actor,
            &Command::Create(crate::domain::Create {
                request_key: "fixture-create".into(),
                name: "Fixture".into(),
                purpose: "Group observer reads".into(),
                acceptance: None,
            }),
        )?
        else {
            return Err("fixture receipt".into());
        };
        Ok((Arc::new(Mutex::new(initial)), receipt.pool_id))
    }

    /// Minimal resident config naming only absent fixture endpoints under `path`.
    fn fixture_config(path: &Path, uid: u32) -> Config {
        Config {
            socket_path: path.join("pool.sock"),
            database_path: path.join("pool.db"),
            expected_uid: uid,
            bridge_registration_socket: path.join("absent-registration.sock"),
            bridge_core_socket: path.join("absent-core.sock"),
            bridge_credential_file: path.join("absent-producer.token"),
            bridge_producer_id: "fixture".into(),
            bridge_audience: "fixture".into(),
            bridge_server_executable: "/fixture/bridge".into(),
            bridge_server_sha256: "0".repeat(64),
            bridge_observer_socket: None,
            bridge_observer_credential_file: None,
            owner_observer_credential_file: None,
            run_socket: None,
            run_peer_uid: None,
            managed_run_reader: None,
            managed_run_transport: None,
            observer_socket: None,
        }
    }

    /// Private test directory with the given mode; the caller keeps the guard alive.
    fn directory(mode: u32) -> Result<tempfile::TempDir, Box<dyn std::error::Error>> {
        let directory =
            tempfile::tempdir_in(std::env::var_os("TMPDIR").ok_or("task TMPDIR required")?)?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(mode))?;
        Ok(directory)
    }

    /// Sends raw bytes through the production connection handler and returns its one reply.
    async fn exchange_raw(
        store: &SharedStore,
        bytes: Vec<u8>,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        let (server, mut client) = UnixStream::pair()?;
        let (served, reply) = tokio::time::timeout(Duration::from_secs(15), async {
            tokio::join!(connection(server, Arc::clone(store)), async {
                client.write_all(&bytes).await?;
                let mut reply = Vec::new();
                client.read_to_end(&mut reply).await?;
                Ok::<_, std::io::Error>(reply)
            })
        })
        .await?;
        served?;
        let reply = reply?;
        assert_eq!(reply.iter().filter(|byte| **byte == b'\n').count(), 1);
        Ok(serde_json::from_slice(&reply)?)
    }

    /// One JSON request line through the production connection handler.
    async fn exchange(
        store: &SharedStore,
        value: Value,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        let mut bytes = serde_json::to_vec(&value)?;
        bytes.push(b'\n');
        exchange_raw(store, bytes).await
    }

    /// Allowed reads succeed; mutations, native commands, credentials, Run proof, bindings,
    /// owner diagnostics and unknown methods are refused, and the database is unchanged.
    #[tokio::test]
    async fn serves_only_closed_read_set() -> Result<(), Box<dyn std::error::Error>> {
        let directory = directory(0o700)?;
        let (store, pool) = store(directory.path())?;
        let database = directory.path().join("pool.db");
        let wal = directory.path().join("pool.db-wal");
        let before = (fs::read(&database)?, fs::read(&wal)?);
        let identity = json!({"schema_version":1,"operation":"identity","params":{}});
        let response = exchange(&store, identity.clone()).await?;
        assert_eq!(response["kind"], "identity");
        let capabilities = response["data"]["capabilities"]
            .as_array()
            .ok_or("capabilities")?;
        assert!(capabilities.iter().any(|item| item == CAPABILITY));
        assert!(
            capabilities
                .iter()
                .any(|item| item == "inventory_completion_v1")
        );
        assert!(
            capabilities
                .iter()
                .any(|item| item == "completion_record_v1")
        );
        assert!(
            capabilities
                .iter()
                .any(|item| item == "managed_enrollment_v1")
        );
        for withheld in WITHHELD {
            assert!(!capabilities.iter().any(|item| item == withheld));
        }
        for (observe, kind) in [
            (
                json!({"schema_version":1,"operation":"list","params":{}}),
                "pool_page",
            ),
            (
                json!({"schema_version":1,"operation":"inventory_snapshot","params":{"filter":"all","limit":10}}),
                "inventory_snapshot",
            ),
            (
                json!({"schema_version":1,"operation":"get","params":{"pool_id":pool}}),
                "pool_detail",
            ),
            (
                json!({"schema_version":1,"operation":"get","params":{"pool_id":pool,"section":"members"}}),
                "pool_detail",
            ),
            (
                json!({"schema_version":1,"operation":"get","params":{"pool_id":pool,"section":"history"}}),
                "pool_detail",
            ),
            (
                json!({"schema_version":1,"operation":"get","params":{"pool_id":pool,"section":"decisions"}}),
                "pool_detail",
            ),
        ] {
            let response = exchange(&store, observe.clone()).await?;
            assert_eq!(response["kind"], kind, "{observe}: {response}");
            assert!(response.get("error").is_none(), "{observe}: {response}");
            assert!(response["data"].get("bindings").is_none());
        }
        let inventory = exchange(
            &store,
            json!({"schema_version":1,"operation":"inventory_snapshot","params":{"filter":"all","limit":10}}),
        )
        .await?;
        assert_eq!(inventory["data"]["totals"]["total"], "1");
        assert_eq!(inventory["data"]["totals"]["open"], "1");
        // Completion and enrollment views reach the store; this pool simply has neither.
        for (observe, kind) in [
            (
                json!({"schema_version":1,"operation":"completion_get","params":{"pool_id":pool,"completion_id":"absent","section":"header","limit":1}}),
                "completion_page",
            ),
            (
                json!({"schema_version":1,"operation":"enrollment_get","params":{"pool_id":pool,"enrollment_id":"absent"}}),
                "enrollment",
            ),
        ] {
            let response = exchange(&store, observe.clone()).await?;
            assert_eq!(response["kind"], kind, "{observe}: {response}");
            let code = response["error"]["code"].as_str().ok_or("error code")?;
            assert!(
                !matches!(code, "unauthorized" | "invalid"),
                "{observe}: {response}"
            );
        }
        for (observe, kind) in [
            (
                json!({"schema_version":1,"operation":"managed_capacity","params":{}}),
                "managed_capacity",
            ),
            (
                json!({"schema_version":1,"operation":"get","params":{"pool_id":pool,"section":"run_proof","member_id":"member"}}),
                "run_proof",
            ),
            (
                json!({"schema_version":1,"operation":"get","params":{"pool_id":pool,"section":"binding","member_id":"member"}}),
                "pool_detail",
            ),
            (
                json!({"schema_version":1,"operation":"get","params":{"pool_id":pool,"section":"members","include_bindings":true}}),
                "pool_detail",
            ),
        ] {
            let response = exchange(&store, observe.clone()).await?;
            assert_eq!(response["kind"], kind, "{observe}: {response}");
            assert_eq!(
                response["error"]["code"], "unauthorized",
                "{observe}: {response}"
            );
            assert!(response.get("data").is_none());
        }
        for name in crate::tools::definitions()
            .iter()
            .filter_map(|tool| tool["name"].as_str())
            .chain(["replay", "admin", "claim", "settle", "unknown_method"])
        {
            for value in [
                json!({"schema_version":1,"operation":name,"params":{}}),
                json!({"schema_version":1,"operation":"identity","params":{},"command":{"name":name,"arguments":{}}}),
                json!({"method":name,"params":{}}),
                json!({"command":{"name":name,"arguments":{}},"assertion":{"assertion_key":"k","invocation_key":"i"}}),
                json!({"observer_credential":"guess","observe":identity}),
                json!({"managed_begin":{}}),
            ] {
                let response = exchange(&store, value.clone()).await?;
                assert_eq!(response["error"]["code"], "invalid", "{value}: {response}");
                assert!(response.get("data").is_none());
            }
        }
        for bytes in [
            vec![b'x'; MAX_REQUEST + 1],
            b"{}\n{}\n".to_vec(),
            b"\xff\n".to_vec(),
        ] {
            let response = exchange_raw(&store, bytes).await?;
            assert_eq!(response["kind"], "error");
            assert_eq!(response["error"]["code"], "invalid");
        }
        assert_eq!((fs::read(&database)?, fs::read(&wal)?), before);
        Ok(())
    }

    /// The kernel peer UID decides admission before any input is read; a refused or excess
    /// peer receives one refusal line, and the client accepts nothing else from that route.
    #[tokio::test]
    async fn admission_uses_peer_uid_allowlist_and_cap() -> Result<(), Box<dyn std::error::Error>> {
        let uid = UnixStream::pair()?.0.peer_cred()?.uid();
        let other = if uid == 0 { 1 } else { uid - 1 };
        let permits = Arc::new(Semaphore::new(1));
        let (server, mut client) = UnixStream::pair()?;
        assert!(admit(server, &[other], &permits).is_none());
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).await?;
        let refused: Envelope = serde_json::from_slice(&reply)?;
        assert_eq!(refused.kind, "error");
        assert_eq!(
            refused.error.as_ref().map(|error| error.code),
            Some(Fault::Unauthorized)
        );
        let value: Value = serde_json::from_slice(&reply)?;
        assert_eq!(value["error"]["outcome"], "blocked");
        let (server, _client) = UnixStream::pair()?;
        let (_admitted, permit) = admit(server, &[other, uid], &permits).ok_or("allowed uid")?;
        let (excess, mut excess_client) = UnixStream::pair()?;
        assert!(admit(excess, &[uid], &permits).is_none());
        let mut reply = Vec::new();
        excess_client.read_to_end(&mut reply).await?;
        let value: Value = serde_json::from_slice(&reply)?;
        assert_eq!(value["error"]["code"], "unavailable");
        drop(permit);
        let (server, _client) = UnixStream::pair()?;
        assert!(admit(server, &[uid], &permits).is_some());
        Ok(())
    }

    /// Bound endpoint has the configured owner, group and mode; unsafe directories, live or
    /// foreign entries are refused, a stale socket is replaced, and cleanup removes only it.
    #[tokio::test]
    async fn listener_applies_group_mode_and_directory_policy()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = directory(0o750)?;
        let path = directory.path().join("observer.sock");
        let metadata = fs::metadata(directory.path())?;
        let mut config = fixture_config(directory.path(), metadata.uid());
        let mut settings = ObserverSocket {
            path: path.clone(),
            gid: metadata.gid(),
            mode: 0o660,
            allowed_uids: vec![metadata.uid()],
        };
        config.observer_socket = Some(settings.clone());
        let (bound, guard) = super::listener(&config, &settings).await?;
        let socket = fs::symlink_metadata(&path)?;
        assert!(socket.file_type().is_socket());
        assert_eq!(socket.mode() & 0o7777, 0o660);
        assert_eq!(
            (socket.uid(), socket.gid()),
            (metadata.uid(), metadata.gid())
        );
        assert!(matches!(
            listener_result(&config, &settings).await,
            Err(Fault::Conflict)
        ));
        drop(bound);
        drop(guard);
        assert!(!path.exists());
        // A stale socket left by a crashed resident is replaced.
        drop(std::os::unix::net::UnixListener::bind(&path)?);
        assert!(path.exists());
        settings.mode = 0o600;
        let (bound, guard) = super::listener(&config, &settings).await?;
        assert_eq!(fs::symlink_metadata(&path)?.mode() & 0o7777, 0o600);
        drop((bound, guard));
        // A regular file at the path is never removed.
        fs::write(&path, "operator data")?;
        assert!(matches!(
            listener_result(&config, &settings).await,
            Err(Fault::Conflict)
        ));
        assert_eq!(fs::read(&path)?, b"operator data");
        fs::remove_file(&path)?;
        for unsafe_mode in [0o770, 0o755, 0o751] {
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(unsafe_mode))?;
            assert!(matches!(
                listener_result(&config, &settings).await,
                Err(Fault::Unavailable)
            ));
            assert!(!path.exists());
        }
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o750))?;
        // A group the resident cannot assign fails closed and leaves no endpoint behind.
        if metadata.uid() != 0 {
            settings.gid = 0;
            assert!(matches!(
                listener_result(&config, &settings).await,
                Err(Fault::Unavailable)
            ));
            assert!(!path.exists());
        }
        Ok(())
    }

    /// Over the real bound endpoint, an allowlisted peer reads and any other peer is refused
    /// with `unauthorized` before its request is read; the client path is the production one
    /// minus the ancestor policy, which the test directory cannot satisfy.
    #[tokio::test]
    async fn bound_socket_serves_allowed_and_refuses_other_uids()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = directory(0o750)?;
        let private = directory.path().join("state");
        fs::create_dir(&private)?;
        fs::set_permissions(&private, fs::Permissions::from_mode(0o700))?;
        let (store, pool) = store(&private)?;
        let metadata = fs::metadata(directory.path())?;
        let uid = metadata.uid();
        let other = if uid == 0 { 1 } else { uid - 1 };
        let config = fixture_config(directory.path(), uid);
        let settings = ObserverSocket {
            path: directory.path().join("observer.sock"),
            gid: metadata.gid(),
            mode: 0o660,
            allowed_uids: vec![uid],
        };
        let (bound, _guard) = super::listener(&config, &settings).await?;
        let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        let get: Request = serde_json::from_value(
            json!({"schema_version":1,"operation":"get","params":{"pool_id":pool,"section":"overview"}}),
        )?;
        for (allowed, succeeds) in [(vec![uid], true), (vec![other], false), (vec![], false)] {
            let expected = observer::Expected::of(&get)?;
            let bytes = serde_json::to_vec(&get)?;
            let (served, envelope) = tokio::time::timeout(Duration::from_secs(15), async {
                tokio::join!(
                    async {
                        let (stream, _) = bound.accept().await.map_err(|_| Fault::Unavailable)?;
                        match admit(stream, &allowed, &permits) {
                            Some((stream, _permit)) => connection(stream, Arc::clone(&store)).await,
                            None => Ok(()),
                        }
                    },
                    async {
                        let stream = UnixStream::connect(&settings.path)
                            .await
                            .map_err(|_| Fault::Unavailable)?;
                        observer::exchange(stream, bytes, &expected).await
                    }
                )
            })
            .await?;
            served?;
            let envelope = envelope?;
            if succeeds {
                assert_eq!(envelope.kind, "pool_detail");
                assert!(matches!(envelope.data, Some(Data::Detail(_))));
            } else {
                assert_eq!(envelope.kind, "error");
                assert!(envelope.data.is_none());
                assert_eq!(
                    envelope.error.map(|error| error.code),
                    Some(Fault::Unauthorized)
                );
            }
        }
        Ok(())
    }

    /// Binds and immediately releases, returning only the outcome.
    async fn listener_result(config: &Config, settings: &ObserverSocket) -> Result<(), Fault> {
        listener(config, settings).await.map(drop)
    }

    /// The real client exchange talks to the real handler, and its correlation rejects
    /// mismatched families; a refusal before decoding passes through as a typed error.
    #[tokio::test]
    async fn client_exchange_matches_server() -> Result<(), Box<dyn std::error::Error>> {
        let directory = directory(0o700)?;
        let (store, _pool) = store(directory.path())?;
        for (value, kind, success) in [
            (
                json!({"schema_version":1,"operation":"list","params":{}}),
                "pool_page",
                true,
            ),
            (
                json!({"schema_version":1,"operation":"managed_capacity","params":{}}),
                "managed_capacity",
                false,
            ),
        ] {
            let request: Request = serde_json::from_value(value)?;
            let expected = observer::Expected::of(&request)?;
            let bytes = serde_json::to_vec(&request)?;
            let (server, client) = UnixStream::pair()?;
            let (served, envelope) = tokio::time::timeout(Duration::from_secs(15), async {
                tokio::join!(
                    connection(server, Arc::clone(&store)),
                    observer::exchange(client, bytes, &expected)
                )
            })
            .await?;
            served?;
            let envelope = envelope?;
            assert_eq!(envelope.kind, kind);
            assert_eq!(envelope.data.is_some(), success);
        }
        let request: Request =
            serde_json::from_value(json!({"schema_version":1,"operation":"identity","params":{}}))?;
        let expected = observer::Expected::of(&request)?;
        let (server, client) = UnixStream::pair()?;
        assert!(admit(server, &[], &Arc::new(Semaphore::new(1))).is_none());
        let envelope = observer::exchange(client, serde_json::to_vec(&request)?, &expected).await?;
        assert_eq!(envelope.kind, "error");
        assert_eq!(
            envelope.error.map(|error| error.code),
            Some(Fault::Unauthorized)
        );
        Ok(())
    }

    /// The client refuses an endpoint whose ancestors or owner fail the cross-user policy
    /// before connecting; test directories sit under a non-root, non-server-owned ancestor.
    #[tokio::test]
    async fn client_refuses_untrusted_socket_path() -> Result<(), Box<dyn std::error::Error>> {
        let directory = directory(0o750)?;
        let path = directory.path().join("observer.sock");
        let listener = UnixListener::bind(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o660))?;
        let uid = fs::metadata(&path)?.uid();
        let request: Request =
            serde_json::from_value(json!({"schema_version":1,"operation":"identity","params":{}}))?;
        let trusted_ancestors = directory.path().ancestors().skip(1).all(|ancestor| {
            fs::metadata(ancestor).is_ok_and(|meta| meta.uid() == 0 || meta.uid() == uid)
        });
        if !trusted_ancestors {
            assert!(matches!(
                observer::socket_frontend(request.clone(), &path, uid).await,
                Err(Fault::Unavailable)
            ));
        }
        let other = if uid == 0 { 1 } else { uid - 1 };
        assert!(matches!(
            observer::socket_frontend(request.clone(), &path, other).await,
            Err(Fault::Unavailable)
        ));
        assert!(matches!(
            observer::socket_frontend(request, Path::new("relative.sock"), uid).await,
            Err(Fault::Invalid)
        ));
        let accepted = tokio::time::timeout(Duration::from_millis(50), listener.accept()).await;
        assert!(
            accepted.is_err(),
            "client must not connect to an untrusted endpoint"
        );
        Ok(())
    }
}
