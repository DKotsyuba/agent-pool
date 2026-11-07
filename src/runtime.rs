//! One persistent resident, authenticated one-call frontend and owned serial outbox worker.
use crate::{
    config::{Config, private_file, private_parent, private_socket},
    domain::{Actor, Binding, Command, Effect, Fault, Reply, Work},
    integrations::{self, Assertion, EXCHANGE_TIMEOUT, MAX_FRAME},
    store::Store,
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::AsyncWriteExt,
    net::{UnixListener, UnixStream},
    sync::{Semaphore, watch},
    task::JoinSet,
};

/// Resident admission ceiling including connections waiting on the short store lock.
const MAX_CONNECTIONS: usize = 32;
/// Long polls cannot consume all resident connection slots needed by writers.
const MAX_WAITERS: usize = 8;
/// Serial observer/outbox cycle cadence; missed ticks are skipped, never replayed in bursts.
const OBSERVATION_INTERVAL: Duration = Duration::from_secs(5);
/// One SQLite writer shared only through finite blocking store operations.
type SharedStore = Arc<Mutex<Store>>;

/// One private resident request; identity is an issuer secret plus exact invocation, never arguments.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    /// Original authenticated invocation transfer issued to the real frontend process.
    assertion: Assertion,
    /// Strict typed domain command without caller identity fields.
    command: Command,
}

/// Removes only the socket inode created by this resident after every owned task has ended.
struct SocketGuard {
    /// Bound socket path, never an unrelated discovered endpoint.
    path: PathBuf,
    /// Original filesystem device for replacement-safe cleanup.
    device: u64,
    /// Original inode for replacement-safe cleanup.
    inode: u64,
}
impl Drop for SocketGuard {
    /// Best-effort endpoint cleanup; replacement files are preserved and data is never deleted.
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.path)
            .is_ok_and(|metadata| metadata.dev() == self.device && metadata.ino() == self.inode)
            && fs::remove_file(&self.path).is_err()
        {
            eprintln!("resident socket cleanup failed");
        }
    }
}

/// Offloads one bounded store transaction; no mutex guard survives a provider await.
/// Poison or worker panic fails closed rather than continuing potentially damaged state.
async fn stored<T, F>(store: &SharedStore, operation: F) -> Result<T, Fault>
where
    T: Send + 'static,
    F: FnOnce(&mut Store) -> Result<T, Fault> + Send + 'static,
{
    let store = Arc::clone(store);
    tokio::task::spawn_blocking(move || {
        let mut guard = store.lock().map_err(|_| Fault::Internal)?;
        operation(&mut guard)
    })
    .await
    .map_err(|_| Fault::Internal)?
}

/// Executes one actual MCP invocation against an already running resident.
/// Registering original metadata occurs in this process before any IPC forwarding.
/// EOF of this frontend never stops or starts the separately owned resident.
pub async fn frontend(
    command: &Command,
    original_meta: serde_json::Value,
    config_path: &Path,
) -> Result<Reply, Fault> {
    command.validate()?;
    let config_path = config_path.to_owned();
    let config = tokio::task::spawn_blocking(move || Config::load(&config_path))
        .await
        .map_err(|_| Fault::Internal)??;
    integrations::own_uid(config.expected_uid)?;
    let assertion = integrations::register(config.clone(), original_meta).await?;
    let request = Request {
        assertion,
        command: command.clone(),
    };
    let mut bytes = serde_json::to_vec(&request).map_err(|_| Fault::Invalid)?;
    if bytes.len() > MAX_FRAME {
        return Err(Fault::Invalid);
    }
    bytes.push(b'\n');
    // The resident has its own finite assertion and store stages, so allow both exchanges.
    let wait = match command {
        Command::Get(get) => Duration::from_secs_f64(get.wait_seconds),
        _ => Duration::ZERO,
    };
    tokio::time::timeout(EXCHANGE_TIMEOUT * 3 + wait, async {
        let mut stream = integrations::connect(&config.socket_path, config.expected_uid).await?;
        stream
            .write_all(&bytes)
            .await
            .map_err(|_| Fault::Unavailable)?;
        serde_json::from_slice(&integrations::read_frame(&mut stream).await?)
            .map_err(|_| Fault::Unavailable)?
    })
    .await
    .map_err(|_| Fault::Unavailable)?
}

/// Authenticates and executes exactly one private frame, then closes its connection.
/// Every native replay consumes current evidence; the separate owner ingress can only project reads.
async fn connection(
    mut stream: UnixStream,
    config: Config,
    store: SharedStore,
    waits: Arc<Semaphore>,
    stopped: watch::Receiver<bool>,
) -> Result<(), Fault> {
    if stream.peer_cred().map_err(|_| Fault::Unauthorized)?.uid() != config.expected_uid {
        return Err(Fault::Unauthorized);
    }
    let mut wait_expiry = None;
    let result = async {
        let bytes = tokio::time::timeout(EXCHANGE_TIMEOUT, integrations::read_frame(&mut stream))
            .await
            .map_err(|_| Fault::Unavailable)??;
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| Fault::Invalid)?;
        if value.get("observer_credential").is_some() || value.get("observe").is_some() {
            return Ok::<_, Fault>(Err(owner_observation(&bytes, &config, &store).await));
        }
        let request: Request = serde_json::from_slice(&bytes).map_err(|_| Fault::Invalid)?;
        request.command.validate()?;
        let invocation = integrations::consume(config.clone(), request.assertion).await?;
        let actor = invocation.actor().clone();
        if let Command::Add(add) = &request.command {
            let parsed = bridge_sdk::bridge_protocol::NativeAddress::parse(&add.address)
                .map_err(|_| Fault::Invalid)?;
            if parsed.canonical() != add.address {
                return Err(Fault::Invalid);
            }
        }
        let join_binding = if let Command::Join(change) = &request.command {
            Some(verify_managed_join(&store, &actor, &change.pool_id).await?)
        } else {
            None
        };
        if let Command::Get(get) = &request.command
            && get.wait_seconds > 0.0
        {
            let expiry = invocation.expiry();
            wait_expiry = Some(expiry);
            return wait_history(
                &store,
                actor,
                get.clone(),
                waits,
                stopped,
                move |budget| {
                    integrations::recheck_invocation(config.clone(), invocation.clone(), budget)
                },
                move || expiry.check(),
            )
            .await
            .map(Ok);
        }
        stored(&store, move |store| {
            if let Some(expected) = join_binding {
                return store.execute_join(&actor, &request.command, &expected);
            }
            store.execute(&actor, &request.command)
        })
        .await
        .map(Ok)
    }
    .await;
    let mut native = match result {
        Ok(Err(envelope)) => {
            let bytes = crate::observer::encode(&envelope).or_else(|error| {
                crate::observer::encode(&crate::observer::Envelope::failure(&envelope.kind, error))
            })?;
            return tokio::time::timeout(EXCHANGE_TIMEOUT, stream.write_all(&bytes))
                .await
                .map_err(|_| Fault::Unavailable)?
                .map_err(|_| Fault::Unavailable);
        }
        Ok(Ok(reply)) => Ok(reply),
        Err(error) => Err(error),
    };
    if native.is_ok()
        && let Some(expiry) = wait_expiry
        && let Err(error) = expiry.check()
    {
        native = Err(error);
    }
    let mut bytes = serde_json::to_vec(&native).map_err(|_| Fault::Internal)?;
    let mut send_deadline = tokio::time::Instant::now() + EXCHANGE_TIMEOUT;
    if native.is_ok()
        && let Some(expiry) = wait_expiry
    {
        let started = tokio::time::Instant::now();
        match expiry.remaining() {
            Ok(remaining) => send_deadline = send_deadline.min(started + remaining),
            Err(error) => {
                bytes =
                    serde_json::to_vec(&Err::<Reply, Fault>(error)).map_err(|_| Fault::Internal)?;
            }
        }
    }
    if bytes.len() > MAX_FRAME {
        return Err(Fault::Internal);
    }
    bytes.push(b'\n');
    write_until(&mut stream, &bytes, send_deadline).await
}

/// A partial response at the deadline is an unavailable call, never a successful reply.
async fn write_until(
    stream: &mut UnixStream,
    bytes: &[u8],
    deadline: tokio::time::Instant,
) -> Result<(), Fault> {
    let timeout = tokio::time::sleep_until(deadline);
    tokio::pin!(timeout);
    let mut written = 0;
    while written < bytes.len() {
        if tokio::time::Instant::now() >= deadline {
            return Err(Fault::Unavailable);
        }
        let result = tokio::select! {
            biased;
            _ = &mut timeout => return Err(Fault::Unavailable),
            result = stream.write(&bytes[written..]) => result,
        };
        match result {
            Ok(0) => return Err(Fault::Unavailable),
            Ok(count) => written += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(Fault::Unavailable),
        }
    }
    if tokio::time::Instant::now() >= deadline {
        return Err(Fault::Unavailable);
    }
    Ok(())
}

/// Rechecks the original consumed assertion within the wait's bounded deadline and shutdown.
async fn wait_authority<F, Fut>(
    check: &mut F,
    stopped: &mut watch::Receiver<bool>,
    deadline: tokio::time::Instant,
) -> Result<(), Fault>
where
    F: FnMut(Duration) -> Fut,
    Fut: std::future::Future<Output = Result<(), Fault>>,
{
    let end = deadline + Duration::from_millis(100);
    let budget = end
        .saturating_duration_since(tokio::time::Instant::now())
        .min(Duration::from_millis(500));
    if budget.is_zero() || *stopped.borrow() {
        return Err(Fault::Unavailable);
    }
    let checking = check(budget);
    tokio::pin!(checking);
    loop {
        tokio::select! {
            biased;
            changed = stopped.changed() => {
                if changed.is_err() || *stopped.borrow() { return Err(Fault::Unavailable); }
            }
            result = &mut checking => return if tokio::time::Instant::now() >= end { Err(Fault::Unavailable) } else { result },
            _ = tokio::time::sleep_until(end) => return Err(Fault::Unavailable),
        }
    }
}

/// Reads a current membership snapshot without waiting indefinitely for the Store mutex.
async fn wait_snapshot(
    store: &SharedStore,
    actor: &Actor,
    get: &crate::domain::Get,
    stopped: &mut watch::Receiver<bool>,
    deadline: tokio::time::Instant,
) -> Result<Option<Reply>, Fault> {
    let actor = actor.clone();
    let get = get.clone();
    let target = Arc::clone(store);
    let mut read = tokio::task::spawn_blocking(move || {
        let mut guard = match target.try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::WouldBlock) => return Ok(None),
            Err(std::sync::TryLockError::Poisoned(_)) => return Err(Fault::Internal),
        };
        guard.execute(&actor, &Command::Get(get)).map(Some)
    });
    loop {
        tokio::select! {
            biased;
            changed = stopped.changed() => {
                if changed.is_err() || *stopped.borrow() {
                    read.abort();
                    return Err(Fault::Unavailable);
                }
            }
            result = &mut read => {
                if tokio::time::Instant::now() >= deadline + Duration::from_millis(100) {
                    return Err(Fault::Unavailable);
                }
                return result.map_err(|_| Fault::Internal)?;
            },
            _ = tokio::time::sleep_until(deadline + Duration::from_millis(100)) => {
                read.abort();
                return Err(Fault::Unavailable);
            }
        }
    }
}

/// Waits for forward history without holding the writer lock or exhausting all request slots.
/// Each poll rechecks the original assertion and membership; shutdown cancels the pending read.
/// A returned page was captured before the final authority check, with unchanged pool revision.
async fn wait_history<F, Fut, E>(
    store: &SharedStore,
    actor: Actor,
    get: crate::domain::Get,
    waits: Arc<Semaphore>,
    mut stopped: watch::Receiver<bool>,
    mut check: F,
    check_expiry: E,
) -> Result<Reply, Fault>
where
    F: FnMut(Duration) -> Fut,
    Fut: std::future::Future<Output = Result<(), Fault>>,
    E: Fn() -> Result<(), Fault>,
{
    let _permit = waits.try_acquire_owned().map_err(|_| Fault::Unavailable)?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs_f64(get.wait_seconds);
    loop {
        if *stopped.borrow() {
            return Err(Fault::Unavailable);
        }
        wait_authority(&mut check, &mut stopped, deadline).await?;
        let reply = wait_snapshot(store, &actor, &get, &mut stopped, deadline).await?;
        let Some(reply) = reply else {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(Fault::Unavailable);
            }
            tokio::select! {
                _ = tokio::time::sleep(remaining.min(Duration::from_millis(250))) => (),
                changed = stopped.changed() => {
                    if changed.is_err() || *stopped.borrow() { return Err(Fault::Unavailable); }
                }
            }
            continue;
        };
        if *stopped.borrow() {
            return Err(Fault::Unavailable);
        }
        let view = match &reply {
            Reply::View(view) | Reply::OwnerView { view, .. } => view,
            _ => return Err(Fault::Internal),
        };
        let revision = view.pool.revision;
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if !view.events.is_empty() || view.pool.closed || remaining.is_zero() {
            wait_authority(&mut check, &mut stopped, deadline).await?;
            let current = wait_snapshot(store, &actor, &get, &mut stopped, deadline)
                .await?
                .ok_or(Fault::Unavailable)?;
            let current_view = match &current {
                Reply::View(view) | Reply::OwnerView { view, .. } => view,
                _ => return Err(Fault::Internal),
            };
            if *stopped.borrow() {
                return Err(Fault::Unavailable);
            }
            if current_view.pool.revision != revision {
                if tokio::time::Instant::now() >= deadline {
                    return Err(Fault::Unavailable);
                }
                continue;
            }
            check_expiry()?;
            return Ok(reply);
        }
        tokio::select! {
            _ = tokio::time::sleep(remaining.min(Duration::from_millis(250))) => (),
            changed = stopped.changed() => {
                if changed.is_err() || *stopped.borrow() {
                    return Err(Fault::Unavailable);
                }
            }
        }
    }
}

/// Authenticates the separate protected owner grant before a closed read-only Store dispatch.
/// Never consumes assertions, creates actors/membership, executes commands or starts provider work.
async fn owner_observation(
    bytes: &[u8],
    config: &Config,
    store: &SharedStore,
) -> crate::observer::Envelope {
    use crate::observer::{Envelope, Ingress};
    let request = serde_json::from_slice::<Ingress>(bytes);
    let kind = request
        .as_ref()
        .map_or("error", |request| request.observe.kind());
    let result = async {
        let request = request.map_err(|_| Fault::Invalid)?;
        let credential_config = config.clone();
        let credential = tokio::task::spawn_blocking(move || {
            let path = credential_config
                .owner_observer_credential_file
                .as_deref()
                .ok_or(Fault::Unauthorized)?;
            private_parent(path, credential_config.expected_uid)?;
            credential_config.credential(path)
        })
        .await
        .map_err(|_| Fault::Internal)??;
        if request.observer_credential != credential {
            return Err(Fault::Unauthorized);
        }
        request.observe.validate()?;
        if let crate::observer::Operation::Get(args) = &request.observe.operation
            && args.section == "run_proof"
        {
            return owner_run_proof(store, config, args).await;
        }
        stored(store, move |store| store.observe(&request.observe)).await
    }
    .await;
    match result {
        Ok(data) => Envelope::success(kind, data),
        Err(error) => Envelope::failure(kind, error),
    }
}

/// Reads one owner-selected Run status and rechecks the Pool binding after the external snapshot.
async fn owner_run_proof(
    store: &SharedStore,
    config: &Config,
    args: &crate::observer::Get,
) -> Result<crate::observer::Data, Fault> {
    use crate::observer::{Data, RunProof, RunProofAuthority, RunProofReason, RunProofState};
    let pool_id = args.pool_id.clone();
    let member_id = args.member_id.clone().ok_or(Fault::Invalid)?;
    let expected = args.expected_revision;
    let read_pool = pool_id.clone();
    let read_member = member_id.clone();
    let binding = stored(store, move |store| {
        store.run_proof_binding(&read_pool, &read_member, expected)
    })
    .await?;
    let mut output = RunProof {
        pool_id: pool_id.clone(),
        member_id: member_id.clone(),
        pool_revision: binding.revision,
        current: binding.current,
        observed_at_unix_ms: 0,
        state: RunProofState::Unknown,
        reason: Some(RunProofReason::IncompleteBinding),
        store_id: None,
        run_observed_at: None,
        proof: None,
        author_identity: RunProofAuthority::Unknown,
    };
    let target = match (
        binding.binding.run_id.as_deref(),
        binding.binding.run_sequence,
        binding.binding.run_execution_ref.as_deref(),
        binding.binding.run_pin_id.as_deref(),
        binding.binding.run_store_id.as_deref(),
    ) {
        (Some(agent_id), Some(sequence), Some(execution_ref), Some(pin_id), Some(store_id))
            if crate::domain::store_id(store_id).is_ok() =>
        {
            u32::try_from(sequence).ok().map(|sequence| {
                (
                    store_id.to_owned(),
                    crate::run_status::Target {
                        agent_id: agent_id.to_owned(),
                        sequence,
                        execution_ref: execution_ref.to_owned(),
                        pin_id: pin_id.to_owned(),
                    },
                )
            })
        }
        _ => None,
    };
    if let Some((store_id, target)) = target {
        output.store_id = Some(store_id.clone());
        let route_ok = binding.route.as_ref().is_some_and(|route| {
            route.store_id.as_deref() == Some(store_id.as_str())
                && configured_run_route(config).is_ok_and(|configured| {
                    configured.socket == route.socket
                        && configured.expected_uid == route.expected_uid
                        && configured.peer_uid == route.peer_uid
                })
        });
        if !route_ok {
            output.reason = Some(RunProofReason::OriginUnavailable);
        } else {
            match integrations::run_status(config, &store_id, std::slice::from_ref(&target)).await {
                Ok(snapshot) => {
                    let proof = snapshot
                        .items()
                        .next()
                        .ok_or(Fault::Unavailable)?
                        .projection();
                    output.state = RunProofState::Observed;
                    output.reason = None;
                    output.store_id = Some(snapshot.store_id().to_owned());
                    output.run_observed_at = Some(snapshot.observed_at());
                    output.proof = Some(proof);
                }
                Err(_) => output.reason = Some(RunProofReason::RunUnavailable),
            }
        }
    }
    let revision = binding.revision;
    let read_pool = pool_id;
    let read_member = member_id;
    let after = stored(store, move |store| {
        store.run_proof_binding(&read_pool, &read_member, Some(revision))
    })
    .await?;
    if after != binding {
        return Err(Fault::Stale);
    }
    output.observed_at_unix_ms = crate::observer::now()?;
    Ok(Data::RunProof(Box::new(output)))
}

/// Refuses managed enrollment until Run can prove the current execution and caller attempt.
async fn verify_managed_join(
    store: &SharedStore,
    actor: &Actor,
    pool_id: &str,
) -> Result<Binding, Fault> {
    let caller = actor.clone();
    let pool_id = pool_id.to_owned();
    let target = stored(store, move |store| store.join_binding(&caller, &pool_id)).await?;
    if target.run_id.is_some() {
        return Err(Fault::Unavailable);
    }
    Ok(target)
}

/// Binds one protected resident endpoint, refusing a live or nonprivate pre-existing path.
/// A stale private socket is removed only after connection refusal and exclusive store ownership.
async fn listener(config: &Config) -> Result<(UnixListener, SocketGuard), Fault> {
    private_parent(&config.socket_path, config.expected_uid)?;
    match fs::symlink_metadata(&config.socket_path) {
        Ok(_) => {
            private_socket(&config.socket_path, config.expected_uid)?;
            match tokio::time::timeout(EXCHANGE_TIMEOUT, UnixStream::connect(&config.socket_path))
                .await
            {
                Ok(Err(error)) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                    fs::remove_file(&config.socket_path).map_err(|_| Fault::Unavailable)?
                }
                _ => return Err(Fault::Conflict),
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(_) => return Err(Fault::Unavailable),
    }
    let listener = UnixListener::bind(&config.socket_path).map_err(|_| Fault::Unavailable)?;
    let metadata = fs::symlink_metadata(&config.socket_path).map_err(|_| Fault::Unavailable)?;
    let guard = SocketGuard {
        path: config.socket_path.clone(),
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    fs::set_permissions(&config.socket_path, fs::Permissions::from_mode(0o600))
        .map_err(|_| Fault::Unavailable)?;
    private_socket(&config.socket_path, config.expected_uid)?;
    Ok((listener, guard))
}

/// Runs the resident until SIGINT/SIGTERM or a supervised worker failure.
/// Admission closes first; accepted connections and the serial worker are then joined without detaching.
pub async fn serve(config_path: &Path) -> Result<(), Fault> {
    let config_path = config_path.to_owned();
    let config = tokio::task::spawn_blocking(move || Config::load(&config_path))
        .await
        .map_err(|_| Fault::Internal)??;
    integrations::own_uid(config.expected_uid)?;
    private_parent(&config.database_path, config.expected_uid)?;
    for path in [
        &config.database_path,
        &config.database_path.with_extension("lock"),
    ] {
        match fs::symlink_metadata(path) {
            Ok(_) => private_file(path, config.expected_uid)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => return Err(Fault::Unavailable),
        }
    }
    let database_path = config.database_path.clone();
    let store = Arc::new(Mutex::new(
        tokio::task::spawn_blocking(move || Store::open(&database_path))
            .await
            .map_err(|_| Fault::Internal)??,
    ));
    let (listener, _guard) = listener(&config).await?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|_| Fault::Unavailable)?;
    let (stop, stopped) = watch::channel(false);
    let mut worker = tokio::spawn(work(config.clone(), Arc::clone(&store), stopped.clone()));
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let waits = Arc::new(Semaphore::new(MAX_WAITERS));
    let mut connections = JoinSet::new();
    let interrupt = tokio::signal::ctrl_c();
    tokio::pin!(interrupt);
    let mut worker_finished = false;
    let result = loop {
        tokio::select! {
            biased;
            signal = &mut interrupt => break signal.map_err(|_| Fault::Unavailable),
            _ = terminate.recv() => break Ok(()),
            result = &mut worker => {
                worker_finished = true;
                break result.map_err(|_| Fault::Internal).and_then(|result| result);
            }
            result = connections.join_next(), if !connections.is_empty() => {
                if matches!(result, Some(Err(_))) { break Err(Fault::Internal); }
                if matches!(result, Some(Ok(Err(_)))) { eprintln!("resident connection ended without a complete reply"); }
            }
            accepted = listener.accept() => {
                let (stream, _) = match accepted { Ok(value) => value, Err(_) => break Err(Fault::Unavailable) };
                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else { drop(stream); continue; };
                let config = config.clone();
                let store = Arc::clone(&store);
                let waits = Arc::clone(&waits);
                let stopped = stopped.clone();
                connections.spawn(async move { let _permit = permit; connection(stream, config, store, waits, stopped).await });
            }
        }
    };
    drop(listener);
    let _ = stop.send(true);
    let mut final_result = result;
    while let Some(outcome) = connections.join_next().await {
        match outcome {
            Err(_) => final_result = Err(Fault::Internal),
            Ok(Err(_)) => eprintln!("resident connection ended without a complete reply"),
            Ok(Ok(())) => (),
        }
    }
    if !worker_finished {
        match worker.await {
            Ok(Ok(())) => (),
            Ok(Err(error)) => final_result = Err(error),
            Err(_) => final_result = Err(Fault::Internal),
        }
    }
    final_result
}

/// Executes/reconciles one persisted effect and records its truthful terminal or unknown state.
/// Provider awaits happen outside SQLite transactions; frozen parameters precede any publish write.
async fn effect(
    store: &SharedStore,
    config: &Config,
    effect: Effect,
    reconcile: bool,
) -> Result<(), Fault> {
    let single_batch = effect.is_single_batch()?;
    let state = match &effect.work {
        Work::Deliver { .. } => {
            if !reconcile && effect.member_id.is_some() {
                let effect_id = effect.effect_id.clone();
                let binding = stored(store, move |store| store.effect_binding(&effect_id)).await?;
                if binding.is_some_and(|(binding, _)| binding.run_id.is_some()) {
                    return settle(store, effect.effect_id, "unknown").await;
                }
            }
            let params = integrations::publication(&effect)?;
            let value = serde_json::to_value(params).map_err(|_| Fault::Internal)?;
            let effect_id = effect.effect_id.clone();
            let producer = config.bridge_producer_id.clone();
            let (producer, value) = stored(store, move |store| {
                store.freeze_publication(&effect_id, &producer, &value)
            })
            .await?;
            let params = serde_json::from_value(value).map_err(|_| Fault::Internal)?;
            integrations::deliver(config.clone(), producer, params, reconcile)
                .await
                .unwrap_or("unknown")
        }
        Work::Retire { scope } => {
            integrations::retire(config.clone(), effect.effect_id.clone(), scope.clone())
                .await
                .unwrap_or("unknown")
        }
        Work::Start {
            spec, request_key, ..
        } => {
            let effect_id = effect.effect_id.clone();
            let binding = stored(store, move |store| store.effect_binding(&effect_id)).await?;
            let admission = match binding {
                Some((target, current)) => match (target.run_id, target.run_sequence) {
                    (Some(agent_id), Some(sequence)) => {
                        Ok(integrations::Admission { agent_id, sequence })
                    }
                    _ if !current => {
                        return settle(
                            store,
                            effect.effect_id,
                            if reconcile { "unknown" } else { "cancelled" },
                        )
                        .await;
                    }
                    _ => {
                        match freeze_run_route(store, config, &effect.effect_id, reconcile).await {
                            Ok(true) => integrations::start(config, spec, request_key).await,
                            _ => Err(Fault::Unavailable.into()),
                        }
                    }
                },
                None => return Err(Fault::Internal),
            };
            match admission {
                Ok(admission) => {
                    let effect_id = effect.effect_id.clone();
                    let agent_id = admission.agent_id.clone();
                    let sequence = admission.sequence;
                    stored(store, move |store| {
                        store.record_run_admission(&effect_id, &agent_id, sequence)
                    })
                    .await?;
                    resolve_run(
                        store,
                        config,
                        &effect.effect_id,
                        &admission.agent_id,
                        sequence,
                    )
                    .await?
                }
                Err(error) if error.known_unadmitted && !reconcile => {
                    eprintln!("Run admission refused: {}", error.code);
                    "refused"
                }
                Err(error) => {
                    if !reconcile {
                        eprintln!("Run admission outcome unknown: {}", error.code);
                    }
                    "unknown"
                }
            }
        }
        Work::StartBatch {
            request_key,
            jobs,
            retain_history,
            store_fence,
            route: frozen_route,
            ..
        } => {
            if single_batch {
                let effect_id = effect.effect_id.clone();
                let (_, current) = stored(store, move |store| store.effect_binding(&effect_id))
                    .await?
                    .ok_or(Fault::Internal)?;
                if !current {
                    if !reconcile {
                        return settle(store, effect.effect_id, "cancelled").await;
                    }
                    let Some(route) = frozen_route else {
                        return settle(store, effect.effect_id, "cancelled").await;
                    };
                    let Some(expected) = route.store_id.as_deref() else {
                        return settle(store, effect.effect_id, "cancelled").await;
                    };
                    if !configured_run_route(config).is_ok_and(|configured| {
                        configured.socket == route.socket
                            && configured.expected_uid == route.expected_uid
                            && configured.peer_uid == route.peer_uid
                    }) {
                        return settle(store, effect.effect_id, "unknown").await;
                    }
                    return match integrations::batch_receipt(
                        config,
                        request_key,
                        jobs,
                        *retain_history,
                        Some(expected),
                    )
                    .await
                    {
                        Ok(Some(admissions)) => {
                            record_batch(store, &effect.effect_id, Some(expected), admissions)
                                .await?;
                            settle(store, effect.effect_id, "accepted").await
                        }
                        _ => settle(store, effect.effect_id, "unknown").await,
                    };
                }
            }
            let route = freeze_run_route(store, config, &effect.effect_id, reconcile).await;
            let Ok(fresh) = route else {
                return settle(store, effect.effect_id, "unknown").await;
            };
            if (!reconcile && !fresh) || (reconcile && !fresh && !*store_fence) {
                return settle(store, effect.effect_id, "unknown").await;
            }
            let expected_store_id = if *store_fence {
                let id = match integrations::run_store_identity(config).await {
                    Ok(id) => id,
                    Err(_) => return settle(store, effect.effect_id, "unknown").await,
                };
                let effect_id = effect.effect_id.clone();
                let frozen_id = id.clone();
                if stored(store, move |store| {
                    store.record_run_store_id(&effect_id, &frozen_id)
                })
                .await
                .is_err()
                {
                    return settle(store, effect.effect_id, "unknown").await;
                }
                Some(id)
            } else {
                None
            };
            if single_batch {
                match integrations::batch_receipt(
                    config,
                    request_key,
                    jobs,
                    *retain_history,
                    expected_store_id.as_deref(),
                )
                .await
                {
                    Ok(Some(admissions)) => {
                        record_batch(
                            store,
                            &effect.effect_id,
                            expected_store_id.as_deref(),
                            admissions,
                        )
                        .await?;
                        return settle(store, effect.effect_id, "accepted").await;
                    }
                    Ok(None) => {}
                    Err(_) => return settle(store, effect.effect_id, "unknown").await,
                }
            }
            match integrations::start_batch(
                config,
                request_key,
                jobs,
                *retain_history,
                expected_store_id.as_deref(),
            )
            .await
            {
                Ok(admissions) => {
                    record_batch(
                        store,
                        &effect.effect_id,
                        expected_store_id.as_deref(),
                        admissions,
                    )
                    .await?;
                    "accepted"
                }
                Err(error) if error.known_unadmitted && !reconcile => {
                    eprintln!("Run batch admission refused: {}", error.code);
                    "refused"
                }
                Err(error) => {
                    if !reconcile {
                        eprintln!("Run batch admission outcome unknown: {}", error.code);
                    }
                    "unknown"
                }
            }
        }
        Work::Replace { .. } => {
            return replacement_effect(store, config, &effect.effect_id).await;
        }
        Work::ResolveRun => {
            let id = effect.effect_id.clone();
            let (target, _) = stored(store, move |store| store.effect_binding(&id))
                .await?
                .ok_or(Fault::Internal)?;
            let (agent_id, sequence) = target
                .run_id
                .zip(target.run_sequence)
                .ok_or(Fault::Internal)?;
            resolve_run(store, config, &effect.effect_id, &agent_id, sequence).await?
        }
        Work::ReleasePin { pin_id, route } => {
            let Some(route) = route else {
                return settle(store, effect.effect_id, "unknown").await;
            };
            let Some(expected) = route.store_id.as_deref() else {
                return settle(store, effect.effect_id, "unknown").await;
            };
            let configured = configured_run_route(config);
            if !configured.is_ok_and(|configured| {
                configured.socket == route.socket
                    && configured.expected_uid == route.expected_uid
                    && configured.peer_uid == route.peer_uid
            }) {
                return settle(store, effect.effect_id, "unknown").await;
            }
            match integrations::run_store_identity(config).await {
                Ok(current) if current == expected => {
                    match integrations::release_history_pin(config, pin_id, expected).await {
                        Ok(()) => "accepted",
                        Err(_) => "unknown",
                    }
                }
                _ => "unknown",
            }
        }
    };
    settle(store, effect.effect_id, state).await
}

/// Reconciles one claimed replacement without releasing the frozen roster on an unknown outcome.
async fn replacement_effect(
    store: &SharedStore,
    config: &Config,
    effect_id: &str,
) -> Result<(), Fault> {
    let lookup_id = effect_id.to_owned();
    let Some((claimed, token)) =
        stored(store, move |store| store.claim_replacement(&lookup_id)).await?
    else {
        return Ok(());
    };
    let Work::Replace {
        request_key,
        old,
        job,
        route,
        condition,
        submitted,
        ..
    } = claimed.work
    else {
        return Err(Fault::Internal);
    };
    let outcome = async {
        let Some(expected) = route.store_id.as_deref() else {
            return Ok::<Option<&'static str>, Fault>(Some("unknown"));
        };
        if !configured_run_route(config).is_ok_and(|current| {
            current.socket == route.socket
                && current.expected_uid == route.expected_uid
                && current.peer_uid == route.peer_uid
        }) {
            return Ok(Some("unknown"));
        }
        if !integrations::run_store_identity(config)
            .await
            .is_ok_and(|current| current == expected)
        {
            return Ok(Some("unknown"));
        }
        let condition = match condition {
            Some(condition) => condition,
            None => {
                let (Some(agent), Some(sequence), Some(reference), Some(pin)) = (
                    old.run_id.as_ref(),
                    old.run_sequence,
                    old.run_execution_ref.as_ref(),
                    old.run_pin_id.as_ref(),
                ) else {
                    return Ok(Some("unknown"));
                };
                let Ok(sequence) = u32::try_from(sequence) else {
                    return Ok(Some("unknown"));
                };
                let target = crate::run_status::Target {
                    agent_id: agent.clone(),
                    sequence,
                    execution_ref: reference.clone(),
                    pin_id: pin.clone(),
                };
                let Ok(snapshot) = integrations::run_status(config, expected, &[target]).await
                else {
                    return Ok(Some("unknown"));
                };
                let Some(item) = snapshot.items().next() else {
                    return Ok(Some("unknown"));
                };
                let Some(condition) = item.replacement_precondition() else {
                    return Ok(Some(if !submitted && item.replacement_not_ready() {
                        "refused"
                    } else {
                        "unknown"
                    }));
                };
                let id = effect_id.to_owned();
                let claim = token.clone();
                let next = condition.clone();
                stored(store, move |store| {
                    store.freeze_replacement_condition(&id, &claim, &next)
                })
                .await?;
                condition
            }
        };
        let jobs = std::slice::from_ref(&job);
        let conditions = std::slice::from_ref(&condition);
        match integrations::batch_receipt_with_preconditions(
            config,
            &request_key,
            jobs,
            true,
            expected,
            conditions,
        )
        .await
        {
            Ok(Some(admissions)) => {
                record_replacement(store, effect_id, &token, expected, admissions).await?;
                return Ok(None);
            }
            Ok(None) => {}
            Err(_) => return Ok(Some("unknown")),
        }
        let id = effect_id.to_owned();
        let claim = token.clone();
        let first = stored(store, move |store| {
            store.begin_replacement_submit(&id, &claim)
        })
        .await?;
        match integrations::start_batch_with_preconditions(
            config,
            &request_key,
            jobs,
            true,
            expected,
            conditions,
        )
        .await
        {
            Ok(admissions) => {
                record_replacement(store, effect_id, &token, expected, admissions).await?;
                Ok(None)
            }
            Err(error) if first && error.code == "PreconditionFailed" => Ok(Some("refused")),
            Err(_) => Ok(Some("unknown")),
        }
    }
    .await?;
    if let Some(state) = outcome {
        let id = effect_id.to_owned();
        stored(store, move |store| {
            store.settle_replacement(&id, &token, state)
        })
        .await?;
    }
    Ok(())
}

/// Commits exactly one correlated replacement receipt and its roster transition.
async fn record_replacement(
    store: &SharedStore,
    effect_id: &str,
    token: &str,
    expected_store: &str,
    mut admissions: Vec<integrations::BatchAdmission>,
) -> Result<(), Fault> {
    if admissions.len() != 1 {
        return Err(Fault::Unavailable);
    }
    let admission = admissions.pop().ok_or(Fault::Unavailable)?;
    let value = (
        admission.agent_id,
        admission.sequence,
        admission.execution_ref,
        admission.pin_id,
    );
    let id = effect_id.to_owned();
    let token = token.to_owned();
    let expected = expected_store.to_owned();
    stored(store, move |store| {
        store.record_replacement_admission(&id, &token, &expected, &value)
    })
    .await
}

/// Persists one fully verified Run receipt and all member mappings in one Pool transaction.
async fn record_batch(
    store: &SharedStore,
    effect_id: &str,
    expected_store_id: Option<&str>,
    admissions: Vec<integrations::BatchAdmission>,
) -> Result<(), Fault> {
    let id = effect_id.to_owned();
    let expected = expected_store_id.map(str::to_owned);
    let values: Vec<_> = admissions
        .into_iter()
        .map(|value| {
            (
                value.agent_id,
                value.sequence,
                value.execution_ref,
                value.pin_id,
            )
        })
        .collect();
    stored(store, move |store| {
        store.record_batch_admission(&id, expected.as_deref(), &values)
    })
    .await
}

/// Persists or verifies the original Run endpoint before an admission request can leave Pool.
async fn freeze_run_route(
    store: &SharedStore,
    config: &Config,
    effect_id: &str,
    reconcile: bool,
) -> Result<bool, Fault> {
    let route = configured_run_route(config)?;
    let id = effect_id.to_owned();
    stored(store, move |store| {
        store.freeze_run_route(&id, &route, reconcile)
    })
    .await
}

/// Builds the locally configured endpoint identity without assuming a Run database identity.
fn configured_run_route(config: &Config) -> Result<crate::domain::RunRoute, Fault> {
    let socket = config
        .run_socket
        .as_ref()
        .and_then(|path| path.to_str())
        .ok_or(Fault::Unavailable)?;
    Ok(crate::domain::RunRoute {
        socket: socket.to_owned(),
        expected_uid: config.expected_uid,
        peer_uid: config.run_peer_uid,
        store_id: None,
    })
}

/// Keeps a Run admission unbound until attempt-bound native identity proof is available.
async fn resolve_run(
    _store: &SharedStore,
    _config: &Config,
    _effect_id: &str,
    _agent_id: &str,
    _sequence: u64,
) -> Result<&'static str, Fault> {
    // A sampled address and sequence can identify a different execution after retention.
    Ok("unknown")
}

/// Persists one effect result; storage failure stops the worker rather than claiming delivery.
async fn settle(store: &SharedStore, effect_id: String, state: &'static str) -> Result<(), Fault> {
    stored(store, move |store| store.settle_effect(&effect_id, state)).await
}

/// Samples one current membership through its proper provider; missing data is explicitly unknown.
async fn observation(store: &SharedStore, config: &Config, target: Binding) -> Result<(), Fault> {
    let runtime = match (&target.run_id, target.run_sequence, &target.address) {
        (Some(_), _, _) => Ok("unknown".to_owned()),
        (_, _, Some(address)) => integrations::observe(config.clone(), address.clone()).await,
        _ => Ok("unknown".to_owned()),
    }
    .unwrap_or_else(|_| "unknown".to_owned());
    stored(store, move |store| {
        store.observe_member(&target.pool_id, &target.member.member_id, &runtime)
    })
    .await
}

/// Owns serial effects and bounded rotating observations; shutdown is checked between finite exchanges.
/// Unknown delivery uses status only; unknown Run admission retries the same frozen admission key.
async fn work(
    config: Config,
    store: SharedStore,
    mut stopped: watch::Receiver<bool>,
) -> Result<(), Fault> {
    let mut interval = tokio::time::interval(OBSERVATION_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut observation_cursor = 0;
    loop {
        tokio::select! {
            biased;
            changed = stopped.changed() => { if changed.is_err() || *stopped.borrow() { return Ok(()); } }
            _ = interval.tick() => (),
        }
        for _ in 0..32 {
            if *stopped.borrow() {
                return Ok(());
            }
            let next = stored(&store, |store| store.next_effect()).await?;
            let Some(next) = next else {
                break;
            };
            effect(&store, &config, next, false).await?;
        }
        let pending = stored(&store, |store| store.pending_unknown()).await?;
        for pending in pending {
            if *stopped.borrow() {
                return Ok(());
            }
            effect(&store, &config, pending, true).await?;
        }
        let targets = stored(&store, |store| store.observation_targets()).await?;
        for offset in 0..targets.len().min(20) {
            if *stopped.borrow() {
                return Ok(());
            }
            let index = (observation_cursor + offset) % targets.len();
            observation(&store, &config, targets[index].clone()).await?;
        }
        observation_cursor = if targets.is_empty() {
            0
        } else {
            (observation_cursor + 20) % targets.len()
        };
    }
}

/// Local lifecycle checks exercise supervisor contracts without bypassing production authentication.
#[cfg(test)]
mod tests {
    use super::*;

    /// Receives one Run request over an isolated listener using the production framing rules.
    async fn receive_run_request(
        listener: &UnixListener,
    ) -> Result<(UnixStream, serde_json::Value), Box<dyn std::error::Error>> {
        let (mut stream, _) = listener.accept().await?;
        let request = serde_json::from_slice(&integrations::read_frame(&mut stream).await?)?;
        Ok((stream, request))
    }

    /// Returns a correlated Run result to the waiting production client.
    async fn reply_to_run_request(
        mut stream: UnixStream,
        request: &serde_json::Value,
        result: serde_json::Value,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut bytes = serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0", "id": request["id"], "result": result
        }))?;
        bytes.push(b'\n');
        stream.write_all(&bytes).await?;
        Ok(())
    }
    /// Isolated Pool membership already admitted by a synthetic Run receipt.
    struct ReplacementFixture {
        _directory: tempfile::TempDir,
        config: Config,
        listener: UnixListener,
        store: SharedStore,
        effect: Effect,
        target: crate::run_status::Target,
        store_id: String,
        status: serde_json::Value,
        pool_id: String,
        old_id: String,
        new_id: String,
    }
    /// Builds a fenced replacement intent without starting any external process.
    fn replacement_fixture() -> Result<ReplacementFixture, Box<dyn std::error::Error>> {
        use crate::domain::{Change, Create, Replace, Start};
        use serde_json::{Value, json};
        let directory =
            tempfile::tempdir_in(std::env::var_os("TMPDIR").ok_or("task TMPDIR required")?)?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let path = directory.path();
        let config = Config {
            socket_path: path.join("pool.sock"),
            database_path: path.join("pool.db"),
            expected_uid: fs::metadata(path)?.uid(),
            bridge_registration_socket: path.join("absent-register"),
            bridge_core_socket: path.join("absent-bridge"),
            bridge_credential_file: path.join("absent-token"),
            bridge_producer_id: "fixture".into(),
            bridge_audience: "fixture".into(),
            bridge_observer_socket: None,
            bridge_observer_credential_file: None,
            owner_observer_credential_file: None,
            run_socket: Some(path.join("run.sock")),
            run_peer_uid: None,
        };
        let socket = config.run_socket.as_ref().ok_or("Run socket")?;
        let listener = UnixListener::bind(socket)?;
        fs::set_permissions(socket, fs::Permissions::from_mode(0o600))?;
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/fixtures/run-status-v1-success.json"))?;
        let target: crate::run_status::Target =
            serde_json::from_value(fixture["socket"]["request"]["targets"][0].clone())?;
        let store_id = fixture["socket"]["request"]["expected_store_id"]
            .as_str()
            .ok_or("store ID")?
            .to_owned();
        let mut status = fixture["socket"]["result"].clone();
        status.as_object_mut().ok_or("status")?.remove("view");
        let mut store = Store::open(&config.database_path)?;
        let owner = Actor::verified("local/codex/main/owner".into(), "owner", "root")?;
        let Reply::Receipt(created) = store.execute(
            &owner,
            &Command::Create(Create {
                request_key: "create".into(),
                name: "Fixture".into(),
                purpose: "Replacement".into(),
                acceptance: None,
            }),
        )?
        else {
            return Err("create receipt".into());
        };
        let pool_id = created.pool_id.clone();
        let Reply::Receipt(started) = store.execute(
            &owner,
            &Command::Start(Start {
                change: Change {
                    pool_id: pool_id.clone(),
                    expected_revision: created.revision,
                    request_key: "start".into(),
                },
                name: "Original".into(),
                role: "Reviewer".into(),
                task: "Review".into(),
                spec: json!({"task":"Original task","provider":"fixture"}),
            }),
        )?
        else {
            return Err("start receipt".into());
        };
        let old_id = started.created_id.clone().ok_or("old member")?;
        let start = store.next_effect()?.ok_or("start effect")?;
        assert!(store.freeze_run_route(
            &start.effect_id,
            &configured_run_route(&config)?,
            false
        )?);
        store.record_run_store_id(&start.effect_id, &store_id)?;
        store.record_batch_admission(
            &start.effect_id,
            Some(&store_id),
            &[(
                target.agent_id.clone(),
                u64::from(target.sequence),
                target.execution_ref.clone(),
                Some(target.pin_id.clone()),
            )],
        )?;
        let Reply::Receipt(requested) = store.execute(
            &owner,
            &Command::Replace(Replace {
                change: Change {
                    pool_id: pool_id.clone(),
                    expected_revision: started.revision,
                    request_key: "replace".into(),
                },
                member_id: old_id.clone(),
                spec: None,
            }),
        )?
        else {
            return Err("replacement receipt".into());
        };
        let effect = store.next_effect()?.ok_or("replacement effect")?;
        assert_eq!(Some(&effect.effect_id), requested.created_id.as_ref());
        let new_id = requested.created_ids.first().ok_or("new member")?.clone();
        Ok(ReplacementFixture {
            _directory: directory,
            config,
            listener,
            store: Arc::new(Mutex::new(store)),
            effect,
            target,
            store_id,
            status,
            pool_id,
            old_id,
            new_id,
        })
    }
    /// Lost admission ACK and a later refusal never unfreeze the old roster; exact lookup can finish it.
    #[tokio::test]
    async fn replacement_lost_ack_then_late_refusal_keeps_roster_frozen()
    -> Result<(), Box<dyn std::error::Error>> {
        use serde_json::json;
        let fixture = replacement_fixture()?;
        let effect_id = fixture.effect.effect_id.clone();
        let duplicate = fixture.effect.clone();
        let (outcome, intent) = tokio::time::timeout(Duration::from_secs(15), async {
            tokio::join!(effect(&fixture.store, &fixture.config, fixture.effect.clone(), false), async {
                let (stream, request) = receive_run_request(&fixture.listener).await?;
                assert_eq!(request["method"], "capabilities");
                reply_to_run_request(stream, &request, json!({"schema_version":1,"product":"agent-run","store_id":fixture.store_id})).await?;
                let (stream, request) = receive_run_request(&fixture.listener).await?;
                assert_eq!(request["method"], "status");
                assert_eq!(request["params"]["targets"], json!([fixture.target]));
                reply_to_run_request(stream, &request, fixture.status.clone()).await?;
                let (stream, request) = receive_run_request(&fixture.listener).await?;
                assert_eq!(request["method"], "batch_receipt");
                reply_to_run_request(stream, &request, json!({"found":false})).await?;
                let (stream, request) = receive_run_request(&fixture.listener).await?;
                assert_eq!(request["method"], "start_batch");
                assert_eq!(request["params"]["preconditions"], json!([fixture.target]));
                effect(&fixture.store, &fixture.config, duplicate, true).await?;
                assert!(tokio::time::timeout(Duration::from_millis(100), fixture.listener.accept()).await.is_err());
                drop(stream);
                Ok::<_, Box<dyn std::error::Error>>(request["params"].clone())
            })
        }).await?;
        outcome?;
        let intent = intent?;
        let pending = stored(&fixture.store, |store| store.pending_unknown()).await?;
        let retry = pending
            .into_iter()
            .find(|item| item.effect_id == effect_id)
            .ok_or("missing retry")?;
        let (outcome, served) = tokio::time::timeout(Duration::from_secs(15), async {
            tokio::join!(effect(&fixture.store, &fixture.config, retry, true), async {
                let (stream, request) = receive_run_request(&fixture.listener).await?;
                assert_eq!(request["method"], "capabilities");
                reply_to_run_request(stream, &request, json!({"schema_version":1,"product":"agent-run","store_id":fixture.store_id})).await?;
                let (stream, request) = receive_run_request(&fixture.listener).await?;
                assert_eq!(request["method"], "batch_receipt");
                assert_eq!(request["params"], intent);
                reply_to_run_request(stream, &request, json!({"found":false})).await?;
                let (mut stream, request) = receive_run_request(&fixture.listener).await?;
                assert_eq!(request["method"], "start_batch");
                assert_eq!(request["params"], intent);
                let mut bytes = serde_json::to_vec(&json!({"jsonrpc":"2.0","id":request["id"],"error":{"code":-32000,"message":"fixture","data":{"code":"PreconditionFailed","reason":"not_met"}}}))?;
                bytes.push(b'\n');
                stream.write_all(&bytes).await?;
                Ok::<_, Box<dyn std::error::Error>>(())
            })
        }).await?;
        outcome?;
        served?;
        let pending = stored(&fixture.store, |store| store.pending_unknown()).await?;
        let retry = pending
            .into_iter()
            .find(|item| item.effect_id == effect_id && item.state == "unknown")
            .ok_or("late refusal cleared unknown")?;
        let old_id = effect_id.clone();
        let (old, current) = stored(&fixture.store, move |store| store.effect_binding(&old_id))
            .await?
            .ok_or("old binding")?;
        assert!(current);
        assert_eq!(old.member.member_id, fixture.old_id);
        let receipt = json!({"version":1,"store_id":fixture.store_id,"request_id":intent["request_id"],"preconditions":intent["preconditions"],"jobs":[{"index":0,"agent_id":"ag-20261107-010102-0000000009","sequence":1,"execution_ref":format!("ex1_{}","b".repeat(64)),"pin_id":format!("pin_{}",uuid::Uuid::new_v4().simple())}]});
        let (outcome, served) = tokio::time::timeout(Duration::from_secs(15), async {
            tokio::join!(effect(&fixture.store, &fixture.config, retry, true), async {
                let (stream, request) = receive_run_request(&fixture.listener).await?;
                assert_eq!(request["method"], "capabilities");
                reply_to_run_request(stream, &request, json!({"schema_version":1,"product":"agent-run","store_id":fixture.store_id})).await?;
                let (stream, request) = receive_run_request(&fixture.listener).await?;
                assert_eq!(request["method"], "batch_receipt");
                assert_eq!(request["params"], intent);
                reply_to_run_request(stream, &request, json!({"found":true,"receipt":receipt})).await?;
                Ok::<_, Box<dyn std::error::Error>>(())
            })
        }).await?;
        outcome?;
        served?;
        let pool = fixture.pool_id.clone();
        let member = fixture.new_id.clone();
        let new = stored(&fixture.store, move |store| {
            store.run_proof_binding(&pool, &member, None)
        })
        .await?;
        assert!(new.current);
        assert_eq!(
            new.binding.run_id.as_deref(),
            Some("ag-20261107-010102-0000000009")
        );
        assert_eq!(
            new.binding.run_store_id.as_deref(),
            Some(fixture.store_id.as_str())
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(100), fixture.listener.accept())
                .await
                .is_err()
        );
        Ok(())
    }
    /// A proven busy member or first correlated Run refusal leaves the old member and releases the roster fence.
    #[tokio::test]
    async fn replacement_definitive_first_refusal_does_not_admit()
    -> Result<(), Box<dyn std::error::Error>> {
        use serde_json::json;
        for preflight_busy in [true, false] {
            let fixture = replacement_fixture()?;
            let mut status = fixture.status.clone();
            if preflight_busy {
                let item = &mut status["items"][0];
                item["selected"]["raw_status"] = json!("running");
                item["retained_latest"]["raw_status"] = json!("running");
                item["lineage_terminal"] = json!(false);
                item["terminal_outcome"] = serde_json::Value::Null;
                item["success_commit"] = json!("unknown");
                item["cleanup"]["state"] = json!("pending");
            }
            let (outcome, served) = tokio::time::timeout(Duration::from_secs(15), async {
                tokio::join!(effect(&fixture.store, &fixture.config, fixture.effect.clone(), false), async {
                    let (stream, request) = receive_run_request(&fixture.listener).await?;
                    assert_eq!(request["method"], "capabilities");
                    reply_to_run_request(stream, &request, json!({"schema_version":1,"product":"agent-run","store_id":fixture.store_id})).await?;
                    let (stream, request) = receive_run_request(&fixture.listener).await?;
                    assert_eq!(request["method"], "status");
                    reply_to_run_request(stream, &request, status).await?;
                    if !preflight_busy {
                        let (stream, request) = receive_run_request(&fixture.listener).await?;
                        assert_eq!(request["method"], "batch_receipt");
                        reply_to_run_request(stream, &request, json!({"found":false})).await?;
                        let (mut stream, request) = receive_run_request(&fixture.listener).await?;
                        assert_eq!(request["method"], "start_batch");
                        let mut bytes = serde_json::to_vec(&json!({"jsonrpc":"2.0","id":request["id"],"error":{"code":-32000,"message":"fixture","data":{"code":"PreconditionFailed","reason":"not_met"}}}))?;
                        bytes.push(b'\n');
                        stream.write_all(&bytes).await?;
                    }
                    Ok::<_, Box<dyn std::error::Error>>(())
                })
            }).await?;
            outcome?;
            served?;
            assert!(
                tokio::time::timeout(Duration::from_millis(100), fixture.listener.accept())
                    .await
                    .is_err()
            );
            let effect_id = fixture.effect.effect_id.clone();
            assert!(
                !stored(&fixture.store, |store| store.pending_unknown())
                    .await?
                    .iter()
                    .any(|item| item.effect_id == effect_id),
                "replacement remained unknown; preflight_busy={preflight_busy}"
            );
            let pool_id = fixture.pool_id.clone();
            let member_id = fixture.old_id.clone();
            let old = stored(&fixture.store, move |store| {
                store.run_proof_binding(&pool_id, &member_id, None)
            })
            .await?;
            assert!(old.current);
            let owner = Actor::verified("local/codex/main/owner".into(), "owner", "root")?;
            let pool_id = fixture.pool_id.clone();
            stored(&fixture.store, move |store| {
                store.execute(
                    &owner,
                    &Command::Close(crate::domain::Change {
                        pool_id,
                        expected_revision: old.revision,
                        request_key: "close-after-refusal".into(),
                    }),
                )
            })
            .await?;
        }
        Ok(())
    }
    /// A worker that selected an operation before cancellation must not contact Run afterwards.
    #[tokio::test]
    async fn cancelled_replacement_stale_worker_sends_nothing()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = replacement_fixture()?;
        let pool = fixture.pool_id.clone();
        let member = fixture.old_id.clone();
        let binding = stored(&fixture.store, move |store| {
            store.run_proof_binding(&pool, &member, None)
        })
        .await?;
        let owner = Actor::verified("local/codex/main/owner".into(), "owner", "root")?;
        let pool_id = fixture.pool_id.clone();
        let operation_id = fixture.effect.effect_id.clone();
        stored(&fixture.store, move |store| {
            store.execute(
                &owner,
                &Command::CancelReplacement(crate::domain::CancelReplacement {
                    change: crate::domain::Change {
                        pool_id,
                        expected_revision: binding.revision,
                        request_key: "cancel".into(),
                    },
                    operation_id,
                }),
            )
        })
        .await?;
        effect(&fixture.store, &fixture.config, fixture.effect, false).await?;
        assert!(
            tokio::time::timeout(Duration::from_millis(100), fixture.listener.accept())
                .await
                .is_err()
        );
        Ok(())
    }
    /// Returns a correlated machine error whose admission semantics have not been proven.
    async fn capacity_error_run_request(
        mut stream: UnixStream,
        request: &serde_json::Value,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut bytes = serde_json::to_vec(&serde_json::json!({
            "jsonrpc":"2.0", "id":request["id"], "error":{"code":-32000,"message":"synthetic capacity error","data":{"code":"CapacityExhausted"}}
        }))?;
        bytes.push(b'\n');
        stream.write_all(&bytes).await?;
        Ok(())
    }

    /// Waiting reads wake for committed history, honor timeout and stop on revocation or shutdown.
    #[tokio::test]
    async fn history_wait_is_bounded_and_rechecks_membership()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::domain::{Add, Change, Create, Get, Message, Remove, Section};
        let directory =
            tempfile::tempdir_in(std::env::var_os("TMPDIR").ok_or("task TMPDIR required")?)?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let mut initial = Store::open(&directory.path().join("pool.db"))?;
        let owner = Actor::verified("local/codex/main/owner".into(), "owner", "root")?;
        let member = Actor::verified("local/codex/main/member".into(), "member", "root")?;
        let Reply::Receipt(created) = initial.execute(
            &owner,
            &Command::Create(Create {
                request_key: "create".into(),
                name: "Fixture".into(),
                purpose: "Wait".into(),
                acceptance: None,
            }),
        )?
        else {
            return Err("missing receipt".into());
        };
        let pool_id = created.pool_id.clone();
        let mut get = Get {
            pool_id: pool_id.clone(),
            after: created.event.event_id,
            section: Section::History,
            proposal_id: None,
            member_id: None,
            wait_seconds: 2.0,
            reverse: false,
            before: None,
            field: None,
            expected_revision: None,
        };
        for invalid in [-0.1, 25.01, f64::INFINITY, f64::NAN] {
            let mut request = get.clone();
            request.wait_seconds = invalid;
            assert!(matches!(
                Command::Get(request).validate(),
                Err(Fault::Invalid)
            ));
        }
        let mut wrong_section = get.clone();
        wrong_section.section = Section::Overview;
        assert!(matches!(
            Command::Get(wrong_section).validate(),
            Err(Fault::Invalid)
        ));
        let store = Arc::new(Mutex::new(initial));
        let waits = Arc::new(Semaphore::new(1));
        let (stop, stopped) = watch::channel(false);
        let (read, write) = tokio::join!(
            wait_history(
                &store,
                owner.clone(),
                get.clone(),
                Arc::clone(&waits),
                stopped.clone(),
                |_| async { Ok(()) },
                || Ok(())
            ),
            async {
                tokio::time::sleep(Duration::from_millis(30)).await;
                let owner = owner.clone();
                let pool_id = pool_id.clone();
                stored(&store, move |store| {
                    store.execute(
                        &owner,
                        &Command::Post(Message {
                            change: Change {
                                pool_id,
                                expected_revision: created.revision,
                                request_key: "post".into(),
                            },
                            body: "new event".into(),
                        }),
                    )
                })
                .await
            }
        );
        let Reply::OwnerView { view, .. } = read? else {
            return Err("owner view required".into());
        };
        assert_eq!(view.events.len(), 1);
        assert_eq!(view.events[0].body, "new event");
        let Reply::Receipt(posted) = write? else {
            return Err("post receipt".into());
        };
        let checks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&checks);
        let revoked = wait_history(
            &store,
            owner.clone(),
            get.clone(),
            Arc::clone(&waits),
            stopped.clone(),
            move |_| {
                let prior = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async move {
                    if prior == 0 {
                        Ok(())
                    } else {
                        Err(Fault::Unauthorized)
                    }
                }
            },
            || Ok(()),
        )
        .await;
        assert!(matches!(revoked, Err(Fault::Unauthorized)));
        assert_eq!(checks.load(std::sync::atomic::Ordering::SeqCst), 2);
        // A new event between the first snapshot and final authority check must not be
        // returned until a fresh check has covered the new snapshot as well.
        let checks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&checks);
        let race_store = Arc::clone(&store);
        let race_owner = owner.clone();
        let race_pool = pool_id.clone();
        let posted_revision = posted.revision;
        let raced = wait_history(
            &store,
            owner.clone(),
            get.clone(),
            Arc::clone(&waits),
            stopped.clone(),
            move |_| {
                let prior = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let race_store = Arc::clone(&race_store);
                let race_owner = race_owner.clone();
                let race_pool = race_pool.clone();
                async move {
                    if prior == 1 {
                        stored(&race_store, move |store| {
                            store.execute(
                                &race_owner,
                                &Command::Post(Message {
                                    change: Change {
                                        pool_id: race_pool,
                                        expected_revision: posted_revision,
                                        request_key: "race-post".into(),
                                    },
                                    body: "during authority recheck".into(),
                                }),
                            )
                        })
                        .await?;
                    }
                    Ok(())
                }
            },
            || Ok(()),
        )
        .await?;
        let Reply::OwnerView { view, .. } = raced else {
            return Err("owner view required".into());
        };
        assert_eq!(checks.load(std::sync::atomic::Ordering::SeqCst), 4);
        assert_eq!(view.events.len(), 2);
        assert_eq!(view.events[1].body, "during authority recheck");
        get.after = view.events[1].event_id;
        let latest_revision = view.pool.revision;
        get.wait_seconds = 0.05;
        let Reply::OwnerView { view, .. } = wait_history(
            &store,
            owner.clone(),
            get.clone(),
            Arc::clone(&waits),
            stopped.clone(),
            |_| async { Ok(()) },
            || Ok(()),
        )
        .await?
        else {
            return Err("owner view required".into());
        };
        assert!(view.events.is_empty());
        assert!(matches!(
            wait_history(
                &store,
                owner.clone(),
                get.clone(),
                Arc::new(Semaphore::new(0)),
                stopped.clone(),
                |_| async { Ok(()) },
                || Ok(())
            )
            .await,
            Err(Fault::Unavailable)
        ));
        let owner_copy = owner.clone();
        let member_copy = member.clone();
        let pool = pool_id.clone();
        let joined = stored(&store, move |store| {
            let added = store.execute(
                &owner_copy,
                &Command::Add(Add {
                    change: Change {
                        pool_id: pool.clone(),
                        expected_revision: latest_revision,
                        request_key: "add".into(),
                    },
                    address: member_copy.address.clone(),
                    name: "Member".into(),
                    role: "Tester".into(),
                    task: "Wait".into(),
                }),
            )?;
            let Reply::Receipt(added) = added else {
                return Err(Fault::Internal);
            };
            let member_id = added.created_id.clone().ok_or(Fault::Internal)?;
            let binding = store.join_binding(&member_copy, &pool)?;
            let joined = store.execute_join(
                &member_copy,
                &Command::Join(Change {
                    pool_id: pool,
                    expected_revision: added.revision,
                    request_key: "join".into(),
                }),
                &binding,
            )?;
            Ok((joined, member_id))
        })
        .await?;
        let (joined, member_id) = joined;
        let Reply::Receipt(joined) = joined else {
            return Err("join receipt".into());
        };
        get.after = joined.event.event_id;
        get.wait_seconds = 2.0;
        let owner_copy = owner.clone();
        let pool = pool_id.clone();
        let (read, removed) = tokio::join!(
            wait_history(
                &store,
                member,
                get.clone(),
                Arc::clone(&waits),
                stopped.clone(),
                |_| async { Ok(()) },
                || Ok(())
            ),
            async {
                tokio::time::sleep(Duration::from_millis(30)).await;
                stored(&store, move |store| {
                    store.execute(
                        &owner_copy,
                        &Command::Remove(Remove {
                            change: Change {
                                pool_id: pool,
                                expected_revision: joined.revision,
                                request_key: "remove".into(),
                            },
                            member_id,
                        }),
                    )
                })
                .await
            }
        );
        removed?;
        assert!(matches!(read, Err(Fault::Forbidden)));
        stop.send(true)?;
        assert!(matches!(
            wait_history(
                &store,
                owner,
                get,
                waits,
                stopped,
                |_| async { Ok(()) },
                || Ok(())
            )
            .await,
            Err(Fault::Unavailable)
        ));
        Ok(())
    }

    /// A contended Store lock cannot trap a waiter past shutdown or indefinitely past its deadline.
    #[tokio::test]
    async fn history_wait_cancels_when_store_is_busy() -> Result<(), Box<dyn std::error::Error>> {
        use crate::domain::{Create, Get, Section};
        let directory =
            tempfile::tempdir_in(std::env::var_os("TMPDIR").ok_or("task TMPDIR required")?)?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let mut initial = Store::open(&directory.path().join("pool.db"))?;
        let owner = Actor::verified("local/codex/main/owner".into(), "owner", "root")?;
        let Reply::Receipt(created) = initial.execute(
            &owner,
            &Command::Create(Create {
                request_key: "create".into(),
                name: "Fixture".into(),
                purpose: "Wait".into(),
                acceptance: None,
            }),
        )?
        else {
            return Err("missing receipt".into());
        };
        let store = Arc::new(Mutex::new(initial));
        let mut get = Get {
            pool_id: created.pool_id.clone(),
            after: created.event.event_id,
            section: Section::History,
            proposal_id: None,
            member_id: None,
            wait_seconds: 2.0,
            reverse: false,
            before: None,
            field: None,
            expected_revision: None,
        };
        let (locked, ready) = tokio::sync::oneshot::channel();
        let (release, released) = std::sync::mpsc::channel::<()>();
        let holder_store = Arc::clone(&store);
        let holder = tokio::task::spawn_blocking(move || {
            let Ok(_guard) = holder_store.lock() else {
                return;
            };
            let _ = locked.send(());
            let _ = released.recv();
        });
        ready.await?;
        let (stop, stopped) = watch::channel(false);
        let (read, signal) = tokio::join!(
            tokio::time::timeout(
                Duration::from_millis(500),
                wait_history(
                    &store,
                    owner.clone(),
                    get.clone(),
                    Arc::new(Semaphore::new(1)),
                    stopped,
                    |_| async { Ok(()) },
                    || Ok(())
                )
            ),
            async {
                tokio::time::sleep(Duration::from_millis(30)).await;
                stop.send(true)
            },
        );
        signal?;
        assert!(matches!(read?, Err(Fault::Unavailable)));
        get.wait_seconds = 0.05;
        let (_stop, stopped) = watch::channel(false);
        let timed = tokio::time::timeout(
            Duration::from_millis(500),
            wait_history(
                &store,
                owner,
                get,
                Arc::new(Semaphore::new(1)),
                stopped,
                |_| async { Ok(()) },
                || Ok(()),
            ),
        )
        .await?;
        assert!(matches!(timed, Err(Fault::Unavailable)));
        release.send(())?;
        holder.await?;
        let (stop, mut stopped) = watch::channel(false);
        let mut slow_check = |_| async { std::future::pending::<Result<(), Fault>>().await };
        let (checked, signal) = tokio::join!(
            tokio::time::timeout(
                Duration::from_millis(500),
                wait_authority(
                    &mut slow_check,
                    &mut stopped,
                    tokio::time::Instant::now() + Duration::from_secs(2)
                )
            ),
            async {
                tokio::time::sleep(Duration::from_millis(30)).await;
                stop.send(true)
            },
        );
        signal?;
        assert!(matches!(checked?, Err(Fault::Unavailable)));
        Ok(())
    }

    /// An assertion expiring while the final SQLite snapshot waits cannot release a history page.
    #[tokio::test]
    async fn history_wait_rejects_expiry_during_final_snapshot()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::domain::{Create, Get, Section};
        let directory =
            tempfile::tempdir_in(std::env::var_os("TMPDIR").ok_or("task TMPDIR required")?)?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let path = directory.path().join("pool.db");
        let mut initial = Store::open(&path)?;
        let owner = Actor::verified("local/codex/main/owner".into(), "owner", "root")?;
        let Reply::Receipt(created) = initial.execute(
            &owner,
            &Command::Create(Create {
                request_key: "create".into(),
                name: "Fixture".into(),
                purpose: "Expiry".into(),
                acceptance: None,
            }),
        )?
        else {
            return Err("missing receipt".into());
        };
        let get = Get {
            pool_id: created.pool_id,
            after: 0,
            section: Section::History,
            proposal_id: None,
            member_id: None,
            wait_seconds: 2.0,
            reverse: false,
            before: None,
            field: None,
            expected_revision: None,
        };
        let store = Arc::new(Mutex::new(initial));
        let external = Arc::new(Mutex::new(rusqlite::Connection::open(path)?));
        let (locked, ready) = tokio::sync::oneshot::channel();
        let locked = Arc::new(Mutex::new(Some(locked)));
        let checks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let check_external = Arc::clone(&external);
        let check_locked = Arc::clone(&locked);
        let count = Arc::clone(&checks);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis();
        let expiry = integrations::InvocationExpiry::new(
            u64::try_from(now)?,
            u64::try_from(now + 350)?,
            u64::try_from(now)?,
            std::time::Instant::now(),
            Duration::from_millis(u64::try_from(now)?),
        )?;
        let (_stop, stopped) = watch::channel(false);
        let (read, released) = tokio::join!(
            wait_history(
                &store,
                owner,
                get,
                Arc::new(Semaphore::new(1)),
                stopped,
                move |_| {
                    let prior = count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let external = Arc::clone(&check_external);
                    let locked = Arc::clone(&check_locked);
                    async move {
                        if prior == 1 {
                            external
                                .lock()
                                .map_err(|_| Fault::Internal)?
                                .execute_batch("BEGIN IMMEDIATE")?;
                            if let Some(locked) = locked.lock().map_err(|_| Fault::Internal)?.take()
                            {
                                let _ = locked.send(());
                            }
                        }
                        Ok(())
                    }
                },
                move || expiry.check(),
            ),
            async {
                ready.await?;
                tokio::time::timeout(Duration::from_secs(1), async {
                    loop {
                        match store.try_lock() {
                            Err(std::sync::TryLockError::WouldBlock) => break,
                            Ok(guard) => drop(guard),
                            Err(std::sync::TryLockError::Poisoned(_)) => {
                                return Err("poisoned store");
                            }
                        }
                        tokio::time::sleep(Duration::from_millis(2)).await;
                    }
                    Ok(())
                })
                .await??;
                tokio::time::sleep(Duration::from_millis(400)).await;
                assert!(matches!(expiry.check(), Err(Fault::Unauthorized)));
                external
                    .lock()
                    .map_err(|_| "poisoned external connection")?
                    .execute_batch("COMMIT")?;
                Ok::<_, Box<dyn std::error::Error>>(())
            },
        );
        released?;
        assert_eq!(checks.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert!(matches!(read, Err(Fault::Unauthorized)));
        Ok(())
    }

    /// An already expired write refuses before touching an otherwise writable socket.
    #[tokio::test]
    async fn response_write_expired_deadline_sends_no_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        use tokio::io::AsyncReadExt;
        let (mut sender, mut receiver) = UnixStream::pair()?;
        let deadline = tokio::time::Instant::now() - Duration::from_millis(1);
        assert!(matches!(
            write_until(&mut sender, b"success\n", deadline).await,
            Err(Fault::Unavailable)
        ));
        drop(sender);
        let mut received = Vec::new();
        receiver.read_to_end(&mut received).await?;
        assert!(received.is_empty());
        Ok(())
    }

    /// A stalled reader cannot make a partial frame look like a successful bounded write.
    #[tokio::test]
    async fn response_write_timeout_never_confirms_a_partial_frame()
    -> Result<(), Box<dyn std::error::Error>> {
        use tokio::io::AsyncReadExt;
        let (mut sender, mut receiver) = UnixStream::pair()?;
        sender.writable().await?;
        let mut prefilled = 0;
        loop {
            match sender.try_write(&[b'x'; 8192]) {
                Ok(0) => return Err("socket closed before test".into()),
                Ok(written) => prefilled += written,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error.into()),
            }
            if prefilled > 32 * MAX_FRAME {
                return Err("socket backpressure did not appear".into());
            }
        }
        let bytes = vec![b'x'; MAX_FRAME];
        let deadline = tokio::time::Instant::now() + Duration::from_millis(30);
        let result = write_until(&mut sender, &bytes, deadline).await;
        assert!(matches!(result, Err(Fault::Unavailable)));
        drop(sender);
        let mut received = Vec::new();
        receiver.read_to_end(&mut received).await?;
        assert!(received.len() < prefilled + bytes.len());
        Ok(())
    }

    /// A late failed request cannot undo a receipt already recovered by a concurrent replay.
    #[tokio::test]
    async fn batch_late_error_preserves_reconciled_receipt()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::domain::{Change, Create, StartBatch, StartMember};
        use serde_json::json;
        let directory =
            tempfile::tempdir_in(std::env::var_os("TMPDIR").ok_or("task TMPDIR required")?)?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let path = directory.path();
        let config = Config {
            socket_path: path.join("pool.sock"),
            database_path: path.join("pool.db"),
            expected_uid: fs::metadata(path)?.uid(),
            bridge_registration_socket: path.join("absent-bridge.sock"),
            bridge_core_socket: path.join("absent-core.sock"),
            bridge_credential_file: path.join("absent-token"),
            bridge_producer_id: "fixture".into(),
            bridge_audience: "fixture-backend".into(),
            bridge_observer_socket: None,
            bridge_observer_credential_file: None,
            owner_observer_credential_file: None,
            run_socket: Some(path.join("run.sock")),
            run_peer_uid: None,
        };
        let socket = config.run_socket.as_ref().ok_or("missing socket")?;
        let listener = UnixListener::bind(socket)?;
        fs::set_permissions(socket, fs::Permissions::from_mode(0o600))?;
        let mut initial = Store::open(&config.database_path)?;
        let owner = Actor::verified("local/codex/main/owner".into(), "owner", "root")?;
        let Reply::Receipt(created) = initial.execute(
            &owner,
            &Command::Create(Create {
                request_key: "create".into(),
                name: "Fixture".into(),
                purpose: "Concurrent recovery".into(),
                acceptance: None,
            }),
        )?
        else {
            return Err("missing create receipt".into());
        };
        initial.execute(
            &owner,
            &Command::StartBatch(StartBatch {
                change: Change {
                    pool_id: created.pool_id,
                    expected_revision: created.revision,
                    request_key: "batch".into(),
                },
                members: vec![StartMember {
                    name: "One".into(),
                    role: "Tester".into(),
                    task: "Verify".into(),
                    spec: json!({"task":"Verify","provider":"codex"}),
                }],
            }),
        )?;
        let claimed = initial.next_effect()?.ok_or("missing batch effect")?;
        let effect_id = claimed.effect_id.clone();
        let store = Arc::new(Mutex::new(initial));
        let store_identity = format!("store_{}", "1".repeat(32));
        let execution_ref = format!("ex1_{}", "a".repeat(64));
        let pin = format!("pin_{}", uuid::Uuid::new_v4().simple());
        let (first_sent, first_seen) = tokio::sync::oneshot::channel();
        let (reconciled, release_original) = tokio::sync::oneshot::channel();
        let original = effect(&store, &config, claimed.clone(), false);
        let retry = async {
            first_seen.await?;
            effect(&store, &config, claimed, false).await?;
            let pending = stored(&store, |store| store.pending_unknown()).await?;
            let retry = pending
                .into_iter()
                .find(|item| item.effect_id == effect_id && item.state == "unknown")
                .ok_or("duplicate dispatch did not leave an unknown intent")?;
            effect(&store, &config, retry, true).await?;
            reconciled.send(()).map_err(|_| "fixture server stopped")?;
            Ok::<_, Box<dyn std::error::Error>>(())
        };
        let server = async {
            let (stream, capabilities) = receive_run_request(&listener).await?;
            reply_to_run_request(
                stream,
                &capabilities,
                json!({"schema_version":1,"product":"agent-run","store_id":store_identity}),
            )
            .await?;
            let (original_stream, original_request) = receive_run_request(&listener).await?;
            first_sent.send(()).map_err(|_| "fixture caller stopped")?;
            let (stream, capabilities) = receive_run_request(&listener).await?;
            reply_to_run_request(
                stream,
                &capabilities,
                json!({"schema_version":1,"product":"agent-run","store_id":store_identity}),
            )
            .await?;
            let (stream, request) = receive_run_request(&listener).await?;
            assert_eq!(original_request["params"], request["params"]);
            reply_to_run_request(stream, &request, json!({"replayed":true,"receipt":{"version":1,"store_id":store_identity,"request_id":request["params"]["request_id"],"jobs":[{"index":0,"agent_id":"ag-20261107-010101-0000000001","sequence":1,"execution_ref":execution_ref,"pin_id":pin}]}})).await?;
            release_original.await?;
            capacity_error_run_request(original_stream, &original_request).await?;
            Ok::<_, Box<dyn std::error::Error>>(())
        };
        let (original, retry, server) = tokio::time::timeout(Duration::from_secs(20), async {
            tokio::join!(original, retry, server)
        })
        .await?;
        original?;
        retry?;
        server?;
        let pending = stored(&store, |store| store.pending_unknown()).await?;
        assert!(
            !pending
                .iter()
                .any(|item| matches!(item.work, Work::StartBatch { .. }))
        );
        let resolver = pending
            .into_iter()
            .find(|item| matches!(item.work, Work::ResolveRun))
            .ok_or("missing resolver")?;
        let (binding, current) = stored(&store, move |store| {
            store.effect_binding(&resolver.effect_id)
        })
        .await?
        .ok_or("missing binding")?;
        assert!(current);
        assert_eq!(
            binding.run_id.as_deref(),
            Some("ag-20261107-010101-0000000001")
        );
        assert_eq!(
            binding.run_execution_ref.as_deref(),
            Some(execution_ref.as_str())
        );
        assert_eq!(binding.run_pin_id.as_deref(), Some(pin.as_str()));
        assert_eq!(
            binding.run_store_id.as_deref(),
            Some(store_identity.as_str())
        );
        Ok(())
    }
    /// A first correlated capacity refusal admits no batch and unblocks the owner's roster.
    #[tokio::test]
    async fn batch_first_capacity_refusal_is_definitive() -> Result<(), Box<dyn std::error::Error>>
    {
        use crate::domain::{Change, Create, StartBatch, StartMember};
        use serde_json::json;
        let directory =
            tempfile::tempdir_in(std::env::var_os("TMPDIR").ok_or("task TMPDIR required")?)?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let path = directory.path();
        let config = Config {
            socket_path: path.join("pool.sock"),
            database_path: path.join("pool.db"),
            expected_uid: fs::metadata(path)?.uid(),
            bridge_registration_socket: path.join("absent-register"),
            bridge_core_socket: path.join("absent-bridge"),
            bridge_credential_file: path.join("absent-token"),
            bridge_producer_id: "fixture".into(),
            bridge_audience: "fixture".into(),
            bridge_observer_socket: None,
            bridge_observer_credential_file: None,
            owner_observer_credential_file: None,
            run_socket: Some(path.join("run.sock")),
            run_peer_uid: None,
        };
        let listener = UnixListener::bind(config.run_socket.as_ref().ok_or("Run socket")?)?;
        fs::set_permissions(path.join("run.sock"), fs::Permissions::from_mode(0o600))?;
        let mut initial = Store::open(&config.database_path)?;
        let owner = Actor::verified("local/codex/main/owner".into(), "owner", "root")?;
        let Reply::Receipt(created) = initial.execute(
            &owner,
            &Command::Create(Create {
                request_key: "create".into(),
                name: "Fixture".into(),
                purpose: "Capacity".into(),
                acceptance: None,
            }),
        )?
        else {
            return Err("create receipt".into());
        };
        let pool_id = created.pool_id.clone();
        let Reply::Receipt(started) = initial.execute(
            &owner,
            &Command::StartBatch(StartBatch {
                change: Change {
                    pool_id: pool_id.clone(),
                    expected_revision: created.revision,
                    request_key: "batch".into(),
                },
                members: ["one", "two"]
                    .into_iter()
                    .map(|name| StartMember {
                        name: name.into(),
                        role: "Tester".into(),
                        task: "Verify".into(),
                        spec: json!({"task":"Verify","provider":"fixture"}),
                    })
                    .collect(),
            }),
        )?
        else {
            return Err("batch receipt".into());
        };
        let claimed = initial.next_effect()?.ok_or("batch effect")?;
        let effect_id = claimed.effect_id.clone();
        let store = Arc::new(Mutex::new(initial));
        let (outcome, served) = tokio::time::timeout(Duration::from_secs(15), async {
            tokio::join!(effect(&store, &config, claimed, false), async {
                let (stream, request) = receive_run_request(&listener).await?;
                assert_eq!(request["method"], "capabilities");
                reply_to_run_request(stream, &request, json!({"schema_version":1,"product":"agent-run","store_id":format!("store_{}","1".repeat(32))})).await?;
                let (stream, request) = receive_run_request(&listener).await?;
                assert_eq!(request["method"], "start_batch");
                capacity_error_run_request(stream, &request).await
            })
        }).await?;
        outcome?;
        served?;
        let pending = stored(&store, |store| store.pending_unknown()).await?;
        assert!(!pending.iter().any(|item| item.effect_id == effect_id));
        let pool = pool_id.clone();
        let member = started.created_ids[0].clone();
        let binding = stored(&store, move |store| {
            store.run_proof_binding(&pool, &member, None)
        })
        .await?;
        assert!(binding.binding.run_id.is_none());
        let leader = owner.clone();
        stored(&store, move |store| {
            store.execute(
                &leader,
                &Command::Close(Change {
                    pool_id,
                    expected_revision: binding.revision,
                    request_key: "close".into(),
                }),
            )
        })
        .await?;
        Ok(())
    }

    /// Unknown fenced admissions replay only against the same Run store, never a drifted route.
    #[tokio::test]
    async fn batch_admission_replays_only_same_verified_store()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::domain::{Change, Create, StartBatch, StartMember};
        use serde_json::json;
        let directory =
            tempfile::tempdir_in(std::env::var_os("TMPDIR").ok_or("task TMPDIR required")?)?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let path = directory.path();
        let config = Config {
            socket_path: path.join("pool.sock"),
            database_path: path.join("pool.db"),
            expected_uid: fs::metadata(path)?.uid(),
            bridge_registration_socket: path.join("absent-bridge.sock"),
            bridge_core_socket: path.join("absent-core.sock"),
            bridge_credential_file: path.join("absent-token"),
            bridge_producer_id: "fixture".into(),
            bridge_audience: "fixture-backend".into(),
            bridge_observer_socket: None,
            bridge_observer_credential_file: None,
            owner_observer_credential_file: None,
            run_socket: Some(path.join("run.sock")),
            run_peer_uid: None,
        };
        let socket = config.run_socket.as_ref().ok_or("missing socket")?;
        let listener = UnixListener::bind(socket)?;
        fs::set_permissions(socket, fs::Permissions::from_mode(0o600))?;
        let mut initial = Store::open(&config.database_path)?;
        let owner = Actor::verified("local/codex/main/owner".into(), "owner", "root")?;
        let Reply::Receipt(created) = initial.execute(
            &owner,
            &Command::Create(Create {
                request_key: "create".into(),
                name: "Fixture".into(),
                purpose: "Batch recovery".into(),
                acceptance: None,
            }),
        )?
        else {
            return Err("missing create receipt".into());
        };
        let members = ["one", "two"]
            .into_iter()
            .map(|label| StartMember {
                name: label.into(),
                role: "Tester".into(),
                task: "Verify".into(),
                spec: json!({"task":label,"provider":"codex"}),
            })
            .collect();
        let Reply::Receipt(started) = initial.execute(
            &owner,
            &Command::StartBatch(StartBatch {
                change: Change {
                    pool_id: created.pool_id,
                    expected_revision: created.revision,
                    request_key: "batch".into(),
                },
                members,
            }),
        )?
        else {
            return Err("missing batch receipt".into());
        };
        assert_eq!(started.created_ids.len(), 2);
        let claimed = initial.next_effect()?.ok_or("missing batch effect")?;
        let effect_id = claimed.effect_id.clone();
        let store = Arc::new(Mutex::new(initial));
        let store_identity = format!("store_{}", "1".repeat(32));
        let (outcome, first) = tokio::time::timeout(Duration::from_secs(20), async {
            tokio::join!(effect(&store, &config, claimed, false), async {
                let (stream, capabilities) = receive_run_request(&listener).await?;
                assert_eq!(capabilities["method"], "capabilities");
                reply_to_run_request(
                    stream,
                    &capabilities,
                    json!({"schema_version":1,"product":"agent-run","store_id":store_identity}),
                )
                .await?;
                let (stream, request) = receive_run_request(&listener).await?;
                drop(stream);
                Ok::<_, Box<dyn std::error::Error>>(request)
            })
        })
        .await?;
        outcome?;
        let first = first?;
        assert_eq!(first["method"], "start_batch");
        assert_eq!(first["params"]["jobs"].as_array().ok_or("jobs")?.len(), 2);
        assert_eq!(first["params"]["retain_history"], true);
        assert_eq!(first["params"]["expected_store_id"], store_identity);
        let pending = stored(&store, |store| store.pending_unknown()).await?;
        let retry = pending
            .into_iter()
            .find(|item| item.effect_id == effect_id && item.state == "unknown")
            .ok_or("unknown batch missing")?;
        effect(&store, &config, retry.clone(), false).await?;
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err(),
            "a repeated non-reconcile dispatch must not resend"
        );
        let other_store = format!("store_{}", "2".repeat(32));
        let (outcome, capabilities) = tokio::time::timeout(Duration::from_secs(20), async {
            tokio::join!(effect(&store, &config, retry, true), async {
                let (stream, request) = receive_run_request(&listener).await?;
                reply_to_run_request(
                    stream,
                    &request,
                    json!({"schema_version":1,"product":"agent-run","store_id":other_store}),
                )
                .await?;
                Ok::<_, Box<dyn std::error::Error>>(request)
            })
        })
        .await?;
        outcome?;
        assert_eq!(capabilities?["method"], "capabilities");
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err(),
            "a different Run store must not receive the batch"
        );
        drop(store);
        let store = Arc::new(Mutex::new(Store::open(&config.database_path)?));
        let pending = stored(&store, |store| store.pending_unknown()).await?;
        let retry = pending
            .into_iter()
            .find(|item| item.effect_id == effect_id && item.state == "unknown")
            .ok_or("unknown batch lost on restart")?;
        let mut changed = config.clone();
        changed.run_socket = Some(path.join("different.sock"));
        let changed_listener = UnixListener::bind(path.join("different.sock"))?;
        fs::set_permissions(
            path.join("different.sock"),
            fs::Permissions::from_mode(0o600),
        )?;
        effect(&store, &changed, retry, true).await?;
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(100), changed_listener.accept())
                .await
                .is_err()
        );
        let pending = stored(&store, |store| store.pending_unknown()).await?;
        assert!(
            pending
                .iter()
                .any(|item| item.effect_id == effect_id && item.state == "unknown")
        );
        let retry = pending
            .into_iter()
            .find(|item| item.effect_id == effect_id)
            .ok_or("same-store retry")?;
        let (outcome, refused) = tokio::time::timeout(Duration::from_secs(20), async {
            tokio::join!(effect(&store, &config, retry, true), async {
                let (stream, capabilities) = receive_run_request(&listener).await?;
                reply_to_run_request(
                    stream,
                    &capabilities,
                    json!({"schema_version":1,"product":"agent-run","store_id":store_identity}),
                )
                .await?;
                let (stream, request) = receive_run_request(&listener).await?;
                capacity_error_run_request(stream, &request).await?;
                Ok::<_, Box<dyn std::error::Error>>(request)
            })
        })
        .await?;
        outcome?;
        assert_eq!(first["params"], refused?["params"]);
        let retry = stored(&store, |store| store.pending_unknown())
            .await?
            .into_iter()
            .find(|item| item.effect_id == effect_id && item.state == "unknown")
            .ok_or("late capacity refusal cleared unknown")?;
        let pin_one = format!("pin_{}", uuid::Uuid::new_v4().simple());
        let pin_two = format!("pin_{}", uuid::Uuid::new_v4().simple());
        let (outcome, wrong_receipt) = tokio::time::timeout(Duration::from_secs(20), async {
            tokio::join!(effect(&store, &config, retry, true), async {
                let (stream, capabilities) = receive_run_request(&listener).await?;
                reply_to_run_request(stream, &capabilities, json!({"schema_version":1,"product":"agent-run","store_id":store_identity})).await?;
                let (stream, request) = receive_run_request(&listener).await?;
                reply_to_run_request(stream, &request, json!({"replayed":true,"receipt":{"version":1,"store_id":other_store,"request_id":request["params"]["request_id"],"jobs":[{"index":0,"agent_id":"ag-20261107-010101-0000000001","sequence":1,"execution_ref":format!("ex1_{}","a".repeat(64)),"pin_id":pin_one},{"index":1,"agent_id":"ag-20261107-010101-0000000002","sequence":1,"execution_ref":format!("ex1_{}","b".repeat(64)),"pin_id":pin_two}]}})).await?;
                Ok::<_, Box<dyn std::error::Error>>(request)
            })
        }).await?;
        outcome?;
        assert_eq!(first["params"], wrong_receipt?["params"]);
        let retry = stored(&store, |store| store.pending_unknown())
            .await?
            .into_iter()
            .find(|item| item.effect_id == effect_id && item.state == "unknown")
            .ok_or("mismatched receipt must remain unknown")?;
        let (outcome, replay) = tokio::time::timeout(Duration::from_secs(20), async {
            tokio::join!(effect(&store, &config, retry, true), async {
                let (stream, capabilities) = receive_run_request(&listener).await?;
                reply_to_run_request(stream, &capabilities, json!({"schema_version":1,"product":"agent-run","store_id":store_identity})).await?;
                let (stream, request) = receive_run_request(&listener).await?;
                reply_to_run_request(stream, &request, json!({"replayed":true,"receipt":{"version":1,"store_id":store_identity,"request_id":request["params"]["request_id"],"jobs":[{"index":0,"agent_id":"ag-20261107-010101-0000000001","sequence":1,"execution_ref":format!("ex1_{}","a".repeat(64)),"pin_id":pin_one},{"index":1,"agent_id":"ag-20261107-010101-0000000002","sequence":1,"execution_ref":format!("ex1_{}","b".repeat(64)),"pin_id":pin_two}]}})).await?;
                Ok::<_, Box<dyn std::error::Error>>(request)
            })
        }).await?;
        outcome?;
        assert_eq!(first["params"], replay?["params"]);
        let pending = stored(&store, |store| store.pending_unknown()).await?;
        assert_eq!(
            pending
                .iter()
                .filter(|item| matches!(item.work, Work::ResolveRun))
                .count(),
            2
        );
        assert_eq!(started.created_ids.len(), 2);
        let second_db = path.join("second.db");
        let mut second = Store::open(&second_db)?;
        let Reply::Receipt(created) = second.execute(
            &owner,
            &Command::Create(Create {
                request_key: "second-create".into(),
                name: "Second".into(),
                purpose: "Before I/O".into(),
                acceptance: None,
            }),
        )?
        else {
            return Err("second create".into());
        };
        let members = ["one", "two"]
            .into_iter()
            .map(|label| StartMember {
                name: label.into(),
                role: "Tester".into(),
                task: "Verify".into(),
                spec: json!({"task":label,"provider":"codex"}),
            })
            .collect();
        second.execute(
            &owner,
            &Command::StartBatch(StartBatch {
                change: Change {
                    pool_id: created.pool_id,
                    expected_revision: created.revision,
                    request_key: "second-batch".into(),
                },
                members,
            }),
        )?;
        let claimed = second.next_effect()?.ok_or("second batch missing")?;
        let second_id = claimed.effect_id;
        drop(second);
        let second = Arc::new(Mutex::new(Store::open(&second_db)?));
        let retry = stored(&second, |store| store.pending_unknown())
            .await?
            .into_iter()
            .find(|item| item.effect_id == second_id)
            .ok_or("second retry missing")?;
        let pin_one = format!("pin_{}", uuid::Uuid::new_v4().simple());
        let pin_two = format!("pin_{}", uuid::Uuid::new_v4().simple());
        let (outcome, first_send) = tokio::time::timeout(Duration::from_secs(20), async {
            tokio::join!(effect(&second, &config, retry, true), async {
                let (stream, capabilities) = receive_run_request(&listener).await?;
                reply_to_run_request(stream, &capabilities, json!({"schema_version":1,"product":"agent-run","store_id":store_identity})).await?;
                let (stream, request) = receive_run_request(&listener).await?;
                reply_to_run_request(stream, &request, json!({"replayed":false,"receipt":{"version":1,"store_id":store_identity,"request_id":request["params"]["request_id"],"jobs":[{"index":0,"agent_id":"ag-20261107-010101-0000000001","sequence":1,"execution_ref":format!("ex1_{}","a".repeat(64)),"pin_id":pin_one},{"index":1,"agent_id":"ag-20261107-010101-0000000002","sequence":1,"execution_ref":format!("ex1_{}","b".repeat(64)),"pin_id":pin_two}]}})).await?;
                Ok::<_, Box<dyn std::error::Error>>(request)
            })
        }).await?;
        outcome?;
        assert_eq!(first_send?["method"], "start_batch");
        let pending = stored(&second, |store| store.pending_unknown()).await?;
        assert_eq!(
            pending
                .iter()
                .filter(|item| matches!(item.work, Work::ResolveRun))
                .count(),
            2
        );
        Ok(())
    }

    /// A removed singleton recovers an acknowledged-lost pin only through a read-only lookup.
    #[tokio::test]
    async fn removed_single_batch_recovers_without_resubmitting()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::domain::{Change, Create, Get, ReleaseHistory, Remove, Section, Start};
        use serde_json::json;
        let directory =
            tempfile::tempdir_in(std::env::var_os("TMPDIR").ok_or("task TMPDIR required")?)?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let path = directory.path();
        let config = Config {
            socket_path: path.join("pool.sock"),
            database_path: path.join("pool.db"),
            expected_uid: fs::metadata(path)?.uid(),
            bridge_registration_socket: path.join("absent-bridge.sock"),
            bridge_core_socket: path.join("absent-core.sock"),
            bridge_credential_file: path.join("absent-token"),
            bridge_producer_id: "fixture".into(),
            bridge_audience: "fixture-backend".into(),
            bridge_observer_socket: None,
            bridge_observer_credential_file: None,
            owner_observer_credential_file: None,
            run_socket: Some(path.join("run.sock")),
            run_peer_uid: None,
        };
        let socket = config.run_socket.as_ref().ok_or("missing socket")?;
        let listener = UnixListener::bind(socket)?;
        fs::set_permissions(socket, fs::Permissions::from_mode(0o600))?;
        let mut initial = Store::open(&config.database_path)?;
        let owner = Actor::verified("local/codex/main/owner".into(), "owner", "root")?;
        let Reply::Receipt(created) = initial.execute(
            &owner,
            &Command::Create(Create {
                request_key: "create".into(),
                name: "Fixture".into(),
                purpose: "Single recovery".into(),
                acceptance: None,
            }),
        )?
        else {
            return Err("missing create receipt".into());
        };
        let Reply::Receipt(started) = initial.execute(
            &owner,
            &Command::Start(Start {
                change: Change {
                    pool_id: created.pool_id.clone(),
                    expected_revision: created.revision,
                    request_key: "single".into(),
                },
                name: "One".into(),
                role: "Tester".into(),
                task: "Verify".into(),
                spec: json!({"task":"Verify","provider":"codex"}),
            }),
        )?
        else {
            return Err("missing start receipt".into());
        };
        let member_id = started.created_id.clone().ok_or("missing member")?;
        assert!(started.created_ids.is_empty());
        let claimed = initial.next_effect()?.ok_or("missing start effect")?;
        assert!(claimed.is_single_batch()?);
        let effect_id = claimed.effect_id.clone();
        let store = Arc::new(Mutex::new(initial));
        let store_id = format!("store_{}", "1".repeat(32));

        // A Run lacking read-only lookup must not receive a mutating start.
        let (outcome, served) = tokio::time::timeout(Duration::from_secs(20), async {
            tokio::join!(effect(&store, &config, claimed, false), async {
                let (stream, request) = receive_run_request(&listener).await?;
                reply_to_run_request(stream, &request, json!({"schema_version":1,"product":"agent-run","store_id":store_id})).await?;
                let (mut stream, request) = receive_run_request(&listener).await?;
                assert_eq!(request["method"], "batch_receipt");
                let mut bytes = serde_json::to_vec(&json!({"jsonrpc":"2.0","id":request["id"],"error":{"code":-32601,"message":"missing"}}))?;
                bytes.push(b'\n');
                stream.write_all(&bytes).await?;
                Ok::<_, Box<dyn std::error::Error>>(())
            })
        }).await?;
        outcome?;
        served?;
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );

        // Reconciliation while current may submit the same intent after lookup reports no receipt.
        let pending = stored(&store, |store| store.pending_unknown()).await?;
        let retry = pending
            .into_iter()
            .find(|item| item.effect_id == effect_id)
            .ok_or("missing unknown start")?;
        let (outcome, sent) = tokio::time::timeout(Duration::from_secs(20), async {
            tokio::join!(effect(&store, &config, retry, true), async {
                let (stream, capabilities) = receive_run_request(&listener).await?;
                reply_to_run_request(
                    stream,
                    &capabilities,
                    json!({"schema_version":1,"product":"agent-run","store_id":store_id}),
                )
                .await?;
                let (stream, lookup) = receive_run_request(&listener).await?;
                assert_eq!(lookup["method"], "batch_receipt");
                reply_to_run_request(stream, &lookup, json!({"found":false})).await?;
                let (stream, request) = receive_run_request(&listener).await?;
                assert_eq!(request["method"], "start_batch");
                assert_eq!(request["params"], lookup["params"]);
                drop(stream);
                Ok::<_, Box<dyn std::error::Error>>(request["params"].clone())
            })
        })
        .await?;
        outcome?;
        let intent = sent?;
        assert_eq!(intent["retain_history"], true);
        assert_eq!(intent["expected_store_id"], store_id);
        assert_eq!(intent["jobs"].as_array().ok_or("jobs")?.len(), 1);

        // The owner may remove and close even though the original outcome is unknown.
        let owner_for_close = owner.clone();
        let pool_id = created.pool_id.clone();
        let member_for_remove = member_id.clone();
        let closed_revision = stored(&store, move |store| {
            let Reply::OwnerView { view, .. } = store.execute(
                &owner_for_close,
                &Command::Get(Get {
                    pool_id: pool_id.clone(),
                    after: 0,
                    section: Section::Overview,
                    proposal_id: None,
                    member_id: None,
                    wait_seconds: 0.0,
                    reverse: false,
                    before: None,
                    field: None,
                    expected_revision: None,
                }),
            )?
            else {
                return Err(Fault::Internal);
            };
            let Reply::Receipt(removed) = store.execute(
                &owner_for_close,
                &Command::Remove(Remove {
                    change: Change {
                        pool_id: pool_id.clone(),
                        expected_revision: view.pool.revision,
                        request_key: "remove".into(),
                    },
                    member_id: member_for_remove,
                }),
            )?
            else {
                return Err(Fault::Internal);
            };
            let Reply::Receipt(closed) = store.execute(
                &owner_for_close,
                &Command::Close(Change {
                    pool_id,
                    expected_revision: removed.revision,
                    request_key: "close".into(),
                }),
            )?
            else {
                return Err(Fault::Internal);
            };
            Ok(closed.revision)
        })
        .await?;

        // Absence at one snapshot remains unknown and cannot trigger another start.
        let retry = stored(&store, |store| store.pending_unknown())
            .await?
            .into_iter()
            .find(|item| item.effect_id == effect_id)
            .ok_or("missing removed unknown start")?;
        let (outcome, served) = tokio::time::timeout(Duration::from_secs(20), async {
            tokio::join!(effect(&store, &config, retry, true), async {
                let (stream, lookup) = receive_run_request(&listener).await?;
                assert_eq!(lookup["method"], "batch_receipt");
                assert_eq!(lookup["params"], intent);
                reply_to_run_request(stream, &lookup, json!({"found":false})).await?;
                Ok::<_, Box<dyn std::error::Error>>(())
            })
        })
        .await?;
        outcome?;
        served?;
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
        let retry = stored(&store, |store| store.pending_unknown())
            .await?
            .into_iter()
            .find(|item| item.effect_id == effect_id)
            .ok_or("missing unknown after empty lookup")?;

        let reference = format!("ex1_{}", "a".repeat(64));
        let pin = format!("pin_{}", uuid::Uuid::new_v4().simple());
        let (outcome, served) = tokio::time::timeout(Duration::from_secs(20), async {
            tokio::join!(effect(&store, &config, retry, true), async {
                let (stream, lookup) = receive_run_request(&listener).await?;
                assert_eq!(lookup["method"], "batch_receipt");
                assert_eq!(lookup["params"], intent);
                reply_to_run_request(stream, &lookup, json!({"found":true,"receipt":{"version":1,"store_id":store_id,"request_id":intent["request_id"],"jobs":[{"index":0,"agent_id":"ag-20261107-010101-0000000001","sequence":1,"execution_ref":reference,"pin_id":pin}]}})).await?;
                Ok::<_, Box<dyn std::error::Error>>(())
            })
        }).await?;
        outcome?;
        served?;
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
        let id = effect_id.clone();
        let (binding, current) = stored(&store, move |store| store.effect_binding(&id))
            .await?
            .ok_or("missing removed binding")?;
        assert!(!current);
        assert_eq!(
            binding.run_id.as_deref(),
            Some("ag-20261107-010101-0000000001")
        );
        assert_eq!(
            binding.run_execution_ref.as_deref(),
            Some(reference.as_str())
        );
        assert_eq!(binding.run_pin_id.as_deref(), Some(pin.as_str()));
        assert_eq!(binding.run_store_id.as_deref(), Some(store_id.as_str()));
        let pool_id = created.pool_id;
        let release = stored(&store, move |store| {
            store.execute(
                &owner,
                &Command::ReleaseHistory(ReleaseHistory {
                    change: Change {
                        pool_id,
                        expected_revision: closed_revision,
                        request_key: "release".into(),
                    },
                    member_id,
                }),
            )
        })
        .await?;
        assert!(matches!(release, Reply::Receipt(_)));
        Ok(())
    }

    /// Removal cannot mark a start cancelled after its Run request may have been sent.
    #[tokio::test]
    async fn removed_member_cannot_cancel_an_inflight_run_start()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::domain::{Change, Create, Remove, Start};
        use serde_json::json;
        let directory =
            tempfile::tempdir_in(std::env::var_os("TMPDIR").ok_or("task TMPDIR required")?)?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let path = directory.path();
        let config = Config {
            socket_path: path.join("pool.sock"),
            database_path: path.join("pool.db"),
            expected_uid: fs::metadata(path)?.uid(),
            bridge_registration_socket: path.join("absent-bridge.sock"),
            bridge_core_socket: path.join("absent-core.sock"),
            bridge_credential_file: path.join("absent-token"),
            bridge_producer_id: "fixture".into(),
            bridge_audience: "fixture-backend".into(),
            bridge_observer_socket: None,
            bridge_observer_credential_file: None,
            owner_observer_credential_file: None,
            run_socket: Some(path.join("run.sock")),
            run_peer_uid: None,
        };
        let socket = config.run_socket.as_ref().ok_or("missing socket")?;
        let listener = UnixListener::bind(socket)?;
        fs::set_permissions(socket, fs::Permissions::from_mode(0o600))?;
        let mut initial = Store::open(&config.database_path)?;
        let owner = Actor::verified("local/codex/main/owner".into(), "owner", "root")?;
        let Reply::Receipt(created) = initial.execute(
            &owner,
            &Command::Create(Create {
                request_key: "create".into(),
                name: "Fixture".into(),
                purpose: "Removal recovery".into(),
                acceptance: None,
            }),
        )?
        else {
            return Err("missing create receipt".into());
        };
        let Reply::Receipt(started) = initial.execute(
            &owner,
            &Command::Start(Start {
                change: Change {
                    pool_id: created.pool_id.clone(),
                    expected_revision: created.revision,
                    request_key: "start".into(),
                },
                name: "One".into(),
                role: "Tester".into(),
                task: "Verify".into(),
                spec: json!({"task":"Verify","provider":"codex"}),
            }),
        )?
        else {
            return Err("missing start receipt".into());
        };
        let member_id = started.created_id.ok_or("missing member")?;
        let claimed = initial.next_effect()?.ok_or("missing start effect")?;
        let claimed = initial.fixture_legacy_start(&claimed.effect_id)?;
        let effect_id = claimed.effect_id.clone();
        let store = Arc::new(Mutex::new(initial));
        let (sent, received) = tokio::sync::oneshot::channel();
        let (removed, release_reply) = tokio::sync::oneshot::channel();
        let original = effect(&store, &config, claimed.clone(), false);
        let duplicate = async {
            received.await?;
            let remove = Command::Remove(Remove {
                change: Change {
                    pool_id: created.pool_id,
                    expected_revision: started.revision,
                    request_key: "remove".into(),
                },
                member_id,
            });
            stored(&store, move |store| store.execute(&owner, &remove)).await?;
            effect(&store, &config, claimed, false).await?;
            let pending = stored(&store, |store| store.pending_unknown()).await?;
            assert!(pending.iter().any(|item| item.effect_id == effect_id));
            removed.send(()).map_err(|_| "fixture server stopped")?;
            Ok::<_, Box<dyn std::error::Error>>(())
        };
        let server = async {
            let (stream, request) = receive_run_request(&listener).await?;
            assert_eq!(request["method"], "start");
            sent.send(()).map_err(|_| "fixture caller stopped")?;
            release_reply.await?;
            reply_to_run_request(stream, &request, json!({"agent_id":"ag-20261107-010101-0000000001","sequence":1,"created":true,"agent":{"agent_id":"ag-20261107-010101-0000000001","sequence":1}})).await?;
            Ok::<_, Box<dyn std::error::Error>>(())
        };
        let (original, duplicate, server) = tokio::time::timeout(Duration::from_secs(20), async {
            tokio::join!(original, duplicate, server)
        })
        .await?;
        original?;
        duplicate?;
        server?;
        let pending = stored(&store, |store| store.pending_unknown()).await?;
        let start = pending
            .into_iter()
            .find(|item| matches!(item.work, Work::Start { .. }))
            .ok_or("admitted start lost reconciliation")?;
        assert_eq!(start.state, "unknown");
        let (binding, current) =
            stored(&store, move |store| store.effect_binding(&start.effect_id))
                .await?
                .ok_or("missing binding")?;
        assert!(!current);
        assert_eq!(
            binding.run_id.as_deref(),
            Some("ag-20261107-010101-0000000001")
        );
        assert_eq!(binding.run_sequence, Some(1));
        Ok(())
    }

    /// Lost acknowledgements stay unknown; stored Run identities cannot authorize membership or delivery.
    #[tokio::test]
    async fn run_effect_holds_unknown_and_denies_unverified_binding()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::domain::{Change, Create, Start};
        use serde_json::json;

        let directory =
            tempfile::tempdir_in(std::env::var_os("TMPDIR").ok_or("task TMPDIR required")?)?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let path = directory.path();
        let config = Config {
            socket_path: path.join("pool.sock"),
            database_path: path.join("pool.db"),
            expected_uid: fs::metadata(path)?.uid(),
            bridge_registration_socket: path.join("absent-bridge.sock"),
            bridge_core_socket: path.join("absent-core.sock"),
            bridge_credential_file: path.join("absent-token"),
            bridge_producer_id: "fixture".into(),
            bridge_audience: "fixture-backend".into(),
            bridge_observer_socket: None,
            bridge_observer_credential_file: None,
            owner_observer_credential_file: None,
            run_socket: Some(path.join("run.sock")),
            run_peer_uid: None,
        };
        let socket = config.run_socket.as_ref().ok_or("fixture socket missing")?;
        let listener = UnixListener::bind(socket)?;
        fs::set_permissions(socket, fs::Permissions::from_mode(0o600))?;

        let mut initial = Store::open(&config.database_path)?;
        let owner = Actor::verified("local/codex/main/owner".into(), "owner", "root")?;
        let Reply::Receipt(created) = initial.execute(
            &owner,
            &Command::Create(Create {
                request_key: "create".into(),
                name: "Fixture".into(),
                purpose: "Admission recovery".into(),
                acceptance: None,
            }),
        )?
        else {
            return Err("missing creation receipt".into());
        };
        let Reply::Receipt(started) = initial.execute(
            &owner,
            &Command::Start(Start {
                change: Change {
                    pool_id: created.pool_id,
                    expected_revision: created.revision,
                    request_key: "start".into(),
                },
                name: "Fixture member".into(),
                role: "Tester".into(),
                task: "Verify recovery".into(),
                spec: json!({"task":"Original task", "provider":"codex", "model":"fixture", "profile":"ordinary", "workdir":"/unused"}),
            }),
        )? else {
            return Err("missing start receipt".into());
        };
        let member_id = started.created_id.ok_or("missing member ID")?;
        let claimed = initial.next_effect()?.ok_or("missing start effect")?;
        let claimed = initial.fixture_legacy_start(&claimed.effect_id)?;
        let effect_id = claimed.effect_id.clone();
        let Work::Start {
            spec, request_key, ..
        } = &claimed.work
        else {
            return Err("first effect is not start".into());
        };
        let (spec, request_key) = (spec.clone(), request_key.clone());
        assert!(spec["task"].as_str().is_some_and(|task| {
            task.starts_with("Original task") && task.contains("pool_join")
        }));
        assert!(
            spec["required_mcp"]["agent-pool"]
                .as_array()
                .is_some_and(|tools| tools.contains(&json!("pool_join")))
        );
        let store = Arc::new(Mutex::new(initial));

        // Simulate an accepted start whose acknowledgment is lost after the write.
        let (outcome, first_request) = tokio::time::timeout(Duration::from_secs(20), async {
            tokio::join!(effect(&store, &config, claimed, false), async {
                let (stream, request) = receive_run_request(&listener).await?;
                drop(stream);
                Ok::<_, Box<dyn std::error::Error>>(request)
            })
        })
        .await?;
        outcome?;
        let first_request = first_request?;
        assert_eq!(first_request["method"], "start");
        assert_eq!(first_request["params"]["request_id"], request_key);
        let pending = stored(&store, |store| store.pending_unknown()).await?;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].state, "unknown");
        drop(store);

        // A resident restart must reconcile the same intent, including its enriched task.
        let store = Arc::new(Mutex::new(Store::open(&config.database_path)?));
        let pending = stored(&store, |store| store.pending_unknown()).await?;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].effect_id, effect_id);
        let retry = pending.into_iter().next().ok_or("missing retry")?;
        let Work::Start {
            spec: retained_spec,
            request_key: retained_key,
            ..
        } = &retry.work
        else {
            return Err("retry is not start".into());
        };
        assert_eq!(retained_spec, &spec);
        assert_eq!(retained_key, &request_key);

        effect(&store, &config, retry, true).await?;
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err(),
            "unknown scalar start must not be resent without store identity"
        );
        let pending = stored(&store, |store| store.pending_unknown()).await?;
        assert!(
            pending
                .iter()
                .any(|item| item.effect_id == effect_id && item.state == "unknown")
        );
        let known_effect = effect_id.clone();
        stored(&store, move |store| {
            store.record_run_admission(&known_effect, "ag-20261107-010101-0000000003", 7)
        })
        .await?;
        let lookup = effect_id.clone();
        let (binding, current) = stored(&store, move |store| store.effect_binding(&lookup))
            .await?
            .ok_or("missing binding")?;
        assert!(current);
        assert_eq!(binding.member.member_id, member_id);
        assert_eq!(
            binding.run_id.as_deref(),
            Some("ag-20261107-010101-0000000003")
        );
        assert_eq!(binding.run_sequence, Some(7));
        assert_eq!(binding.address, None);

        // Simulate a previously stored address: without attempt proof it grants no access or delivery.
        let old_effect = effect_id.clone();
        stored(&store, move |store| {
            store.bind_run(&old_effect, "local/codex/main/member")
        })
        .await?;
        let pool = binding.pool_id.clone();
        let managed = member_id.clone();
        stored(&store, move |store| {
            store.observe_member(&pool, &managed, "succeeded")
        })
        .await?;
        let pool = binding.pool_id.clone();
        let leader = owner.clone();
        let owner_view = stored(&store, move |store| {
            store.execute(
                &leader,
                &Command::Get(crate::domain::Get {
                    pool_id: pool,
                    after: 0,
                    section: crate::domain::Section::Members,
                    proposal_id: None,
                    member_id: None,
                    wait_seconds: 0.0,
                    reverse: false,
                    before: None,
                    field: None,
                    expected_revision: None,
                }),
            )
        })
        .await?;
        let Reply::OwnerView { view, bindings } = owner_view else {
            return Err("owner view required".into());
        };
        assert_eq!(view.members[0].runtime, "unknown");
        assert_eq!(bindings[0].member.runtime, "unknown");
        let member = Actor::verified("local/codex/main/member".into(), "member", "root")?;
        assert!(matches!(
            verify_managed_join(&store, &member, &binding.pool_id).await,
            Err(Fault::Unavailable)
        ));
        let pool_id = binding.pool_id.clone();
        let actor = member.clone();
        let read = stored(&store, move |store| {
            store.execute(
                &actor,
                &Command::Get(crate::domain::Get {
                    pool_id,
                    after: 0,
                    section: crate::domain::Section::Overview,
                    proposal_id: None,
                    member_id: None,
                    wait_seconds: 0.0,
                    reverse: false,
                    before: None,
                    field: None,
                    expected_revision: None,
                }),
            )
        })
        .await;
        assert!(matches!(read, Err(Fault::Unavailable)));
        let actor = member.clone();
        let list = stored(&store, move |store| {
            store.execute(&actor, &Command::List(crate::domain::List { after: None }))
        })
        .await;
        assert!(matches!(list, Err(Fault::Unavailable)));
        let (_stop, stopped) = watch::channel(false);
        let waiting = wait_history(
            &store,
            member.clone(),
            crate::domain::Get {
                pool_id: binding.pool_id.clone(),
                after: 0,
                section: crate::domain::Section::History,
                proposal_id: None,
                member_id: None,
                wait_seconds: 0.1,
                reverse: false,
                before: None,
                field: None,
                expected_revision: None,
            },
            Arc::new(Semaphore::new(1)),
            stopped,
            |_| async { Ok(()) },
            || Ok(()),
        )
        .await;
        assert!(matches!(waiting, Err(Fault::Unavailable)));
        let mut held = false;
        while let Some(queued) = stored(&store, |store| store.next_effect()).await? {
            if queued.member_id.as_deref() == Some(&member_id)
                && matches!(queued.work, Work::Deliver { .. })
            {
                let id = queued.effect_id.clone();
                effect(&store, &config, queued, false).await?;
                let pending = stored(&store, |store| store.pending_unknown()).await?;
                held = pending
                    .iter()
                    .any(|item| item.effect_id == id && item.state == "unknown");
                break;
            }
        }
        assert!(
            held,
            "unverified Run recipient must not receive a fresh delivery"
        );
        Ok(())
    }

    /// A closed pool can record release intent, but cannot send it to an unverified Run store.
    #[tokio::test]
    async fn pin_release_waits_for_run_store_identity() -> Result<(), Box<dyn std::error::Error>> {
        use crate::domain::{Change, Create, ReleaseHistory, RunRoute, StartBatch, StartMember};
        use serde_json::json;
        let directory =
            tempfile::tempdir_in(std::env::var_os("TMPDIR").ok_or("task TMPDIR required")?)?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let path = directory.path();
        let config = Config {
            socket_path: path.join("pool.sock"),
            database_path: path.join("pool.db"),
            expected_uid: fs::metadata(path)?.uid(),
            bridge_registration_socket: path.join("absent-bridge.sock"),
            bridge_core_socket: path.join("absent-core.sock"),
            bridge_credential_file: path.join("absent-token"),
            bridge_producer_id: "fixture".into(),
            bridge_audience: "fixture-backend".into(),
            bridge_observer_socket: None,
            bridge_observer_credential_file: None,
            owner_observer_credential_file: None,
            run_socket: Some(path.join("run.sock")),
            run_peer_uid: None,
        };
        let listener = UnixListener::bind(config.run_socket.as_ref().ok_or("socket")?)?;
        fs::set_permissions(path.join("run.sock"), fs::Permissions::from_mode(0o600))?;
        let mut store = Store::open(&config.database_path)?;
        let owner = Actor::verified("local/codex/main/owner".into(), "owner", "root")?;
        let Reply::Receipt(created) = store.execute(
            &owner,
            &Command::Create(Create {
                request_key: "create".into(),
                name: "Pool".into(),
                purpose: "Release".into(),
                acceptance: None,
            }),
        )?
        else {
            return Err("create receipt".into());
        };
        let pool_id = created.pool_id.clone();
        let Reply::Receipt(started) = store.execute(
            &owner,
            &Command::StartBatch(StartBatch {
                change: Change {
                    pool_id: pool_id.clone(),
                    expected_revision: created.revision,
                    request_key: "batch".into(),
                },
                members: vec![StartMember {
                    name: "Member".into(),
                    role: "Tester".into(),
                    task: "Check".into(),
                    spec: json!({"task":"Check"}),
                }],
            }),
        )?
        else {
            return Err("batch receipt".into());
        };
        let admission = store.next_effect()?.ok_or("admission effect")?;
        let route = RunRoute {
            socket: path.join("run.sock").to_str().ok_or("path")?.into(),
            expected_uid: config.expected_uid,
            peer_uid: None,
            store_id: None,
        };
        store.freeze_run_route(&admission.effect_id, &route, false)?;
        let store_identity = format!("store_{}", "1".repeat(32));
        store.record_run_store_id(&admission.effect_id, &store_identity)?;
        let pin = format!("pin_{}", uuid::Uuid::new_v4().simple());
        store.record_batch_admission(
            &admission.effect_id,
            Some(&store_identity),
            &[(
                "ag-20261107-010101-0000000003".into(),
                1,
                format!("ex1_{}", "a".repeat(64)),
                Some(pin.clone()),
            )],
        )?;
        let Reply::Receipt(closed) = store.execute(
            &owner,
            &Command::Close(Change {
                pool_id: pool_id.clone(),
                expected_revision: started.revision,
                request_key: "close".into(),
            }),
        )?
        else {
            return Err("close receipt".into());
        };
        let Reply::Receipt(requested) = store.execute(
            &owner,
            &Command::ReleaseHistory(ReleaseHistory {
                change: Change {
                    pool_id,
                    expected_revision: closed.revision,
                    request_key: "release".into(),
                },
                member_id: started.created_ids[0].clone(),
            }),
        )?
        else {
            return Err("release receipt".into());
        };
        let release_id = requested.created_id.ok_or("release ID")?;
        let release = loop {
            let next = store.next_effect()?.ok_or("release effect")?;
            if next.effect_id == release_id {
                break next;
            }
        };
        let store = Arc::new(Mutex::new(store));
        let wrong = format!("store_{}", "2".repeat(32));
        let (outcome, _) = tokio::time::timeout(Duration::from_secs(20), async {
            tokio::join!(effect(&store, &config, release, false), async {
                let (stream, request) = receive_run_request(&listener).await?;
                reply_to_run_request(
                    stream,
                    &request,
                    json!({"schema_version":1,"product":"agent-run","store_id":wrong}),
                )
                .await?;
                Ok::<_, Box<dyn std::error::Error>>(())
            })
        })
        .await?;
        outcome?;
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
        drop(store);
        let store = Arc::new(Mutex::new(Store::open(&config.database_path)?));
        let retry = stored(&store, |store| store.pending_unknown())
            .await?
            .into_iter()
            .find(|item| item.effect_id == release_id)
            .ok_or("release retry")?;
        assert_eq!(retry.state, "unknown");
        let (outcome, first_release) = tokio::time::timeout(Duration::from_secs(20), async {
            tokio::join!(effect(&store, &config, retry, true), async {
                let (stream, capabilities) = receive_run_request(&listener).await?;
                reply_to_run_request(
                    stream,
                    &capabilities,
                    json!({"schema_version":1,"product":"agent-run","store_id":store_identity}),
                )
                .await?;
                let (stream, request) = receive_run_request(&listener).await?;
                drop(stream);
                Ok::<_, Box<dyn std::error::Error>>(request)
            })
        })
        .await?;
        outcome?;
        let first_release = first_release?;
        assert_eq!(first_release["method"], "history_pins");
        assert_eq!(
            first_release["params"],
            json!({"action":"release","pin_id":pin,"expected_store_id":store_identity})
        );
        drop(store);
        let store = Arc::new(Mutex::new(Store::open(&config.database_path)?));
        let retry = stored(&store, |store| store.pending_unknown())
            .await?
            .into_iter()
            .find(|item| item.effect_id == release_id)
            .ok_or("release retry after lost ACK")?;
        let (outcome, repeated) = tokio::time::timeout(Duration::from_secs(20), async {
            tokio::join!(effect(&store, &config, retry, true), async {
                let (stream, capabilities) = receive_run_request(&listener).await?;
                reply_to_run_request(
                    stream,
                    &capabilities,
                    json!({"schema_version":1,"product":"agent-run","store_id":store_identity}),
                )
                .await?;
                let (stream, request) = receive_run_request(&listener).await?;
                reply_to_run_request(
                    stream,
                    &request,
                    json!({"pin_id":pin,"status":"released","already_released":true}),
                )
                .await?;
                Ok::<_, Box<dyn std::error::Error>>(request)
            })
        })
        .await?;
        outcome?;
        assert_eq!(first_release["params"], repeated?["params"]);
        let pending = stored(&store, |store| store.pending_unknown()).await?;
        assert!(!pending.iter().any(|item| item.effect_id == release_id));
        Ok(())
    }

    /// Exercises Pool's durable outbox against an explicitly isolated fake-engine Run broker.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires a task-owned synthetic Run fixture and Pool MCP catalog"]
    async fn live_synthetic_pool_outbox() -> Result<(), Box<dyn std::error::Error>> {
        use crate::domain::{Change, Create, ReleaseHistory, StartBatch, StartMember};
        use serde_json::json;
        let root = fs::canonicalize(std::env::var_os("TMPDIR").ok_or("task TMPDIR required")?)?;
        let home = fs::canonicalize(
            std::env::var_os("AGENT_POOL_SYNTHETIC_RUN_HOME").ok_or("fixture home required")?,
        )?;
        if home == root
            || !home.starts_with(&root)
            || fs::read_to_string(home.join(".pool-synthetic-run"))?
                != "agent-pool synthetic fixture\n"
        {
            return Err("refusing non-fixture Run home".into());
        }
        let pool_root = home.join("pool-state");
        fs::create_dir(&pool_root)?;
        fs::set_permissions(&pool_root, fs::Permissions::from_mode(0o700))?;
        let uid = fs::metadata(&pool_root)?.uid();
        let config = Config {
            socket_path: pool_root.join("pool.sock"),
            database_path: pool_root.join("pool.db"),
            expected_uid: uid,
            bridge_registration_socket: pool_root.join("absent-bridge.sock"),
            bridge_core_socket: pool_root.join("absent-core.sock"),
            bridge_credential_file: pool_root.join("absent-token"),
            bridge_producer_id: "fixture".into(),
            bridge_audience: "fixture-backend".into(),
            bridge_observer_socket: None,
            bridge_observer_credential_file: None,
            owner_observer_credential_file: None,
            run_socket: Some(home.join("api.sock")),
            run_peer_uid: None,
        };
        let mut initial = Store::open(&config.database_path)?;
        let owner = Actor::verified("local/codex/main/owner".into(), "owner", "root")?;
        let Reply::Receipt(created) = initial.execute(
            &owner,
            &Command::Create(Create {
                request_key: "create".into(),
                name: "Pool".into(),
                purpose: "Fixture".into(),
                acceptance: None,
            }),
        )?
        else {
            return Err("create receipt".into());
        };
        let pool_id = created.pool_id.clone();
        let members = ["one","two"].into_iter().map(|name| StartMember {
            name:name.into(),role:"Tester".into(),task:"Verify".into(),
            spec:json!({"provider":"glm-user","model":"fixture","profile":"review","explicit_finish":false,"task":"fixture:answer","workdir":home}),
        }).collect();
        let Reply::Receipt(started) = initial.execute(
            &owner,
            &Command::StartBatch(StartBatch {
                change: Change {
                    pool_id: pool_id.clone(),
                    expected_revision: created.revision,
                    request_key: "batch".into(),
                },
                members,
            }),
        )?
        else {
            return Err("batch receipt".into());
        };
        let claimed = initial.next_effect()?.ok_or("batch effect missing")?;
        let effect_id = claimed.effect_id.clone();
        let store = Arc::new(Mutex::new(initial));
        effect(&store, &config, claimed, false).await?;
        let pending = stored(&store, |store| store.pending_unknown()).await?;
        assert!(!pending.iter().any(|item| item.effect_id == effect_id));
        let mut resolved = 0;
        let mut run_ids = Vec::new();
        let mut pins_by_member = std::collections::BTreeMap::new();
        for item in pending
            .into_iter()
            .filter(|item| matches!(item.work, Work::ResolveRun))
        {
            let id = item.effect_id;
            let (binding, current) = stored(&store, move |store| store.effect_binding(&id))
                .await?
                .ok_or("binding missing")?;
            assert!(current);
            assert!(started.created_ids.contains(&binding.member.member_id));
            assert!(binding.run_id.is_some() && binding.run_sequence == Some(1));
            assert!(
                binding.run_execution_ref.is_some()
                    && binding.run_pin_id.is_some()
                    && binding.run_store_id.is_some()
            );
            assert!(binding.address.is_none());
            run_ids.push(binding.run_id.ok_or("run ID")?);
            pins_by_member.insert(
                binding.member.member_id,
                binding.run_pin_id.ok_or("pin ID")?,
            );
            resolved += 1;
        }
        assert_eq!(resolved, 2);
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let db = rusqlite::Connection::open_with_flags(home.join("state.db"), rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
                let running: i64 = db.query_row("SELECT COUNT(*) FROM agents WHERE status IN ('created','starting','running','cancelling')", [], |row| row.get(0))?;
                let active: i64 = db.query_row("SELECT COUNT(*) FROM attempts WHERE ownership_active=1", [], |row| row.get(0))?;
                let mut succeeded = 0;
                for id in &run_ids {
                    let status: String = db.query_row("SELECT status FROM agents WHERE id=?1", [id], |row| row.get(0))?;
                    if status == "succeeded" { succeeded += 1; }
                }
                drop(db);
                if running == 0 && active == 0 && succeeded == run_ids.len() { break Ok::<_, rusqlite::Error>(()); }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }).await??;
        let leader = owner.clone();
        let pool = pool_id.clone();
        let revision = started.revision;
        let closed = stored(&store, move |store| {
            store.execute(
                &leader,
                &Command::Close(Change {
                    pool_id: pool,
                    expected_revision: revision,
                    request_key: "close".into(),
                }),
            )
        })
        .await?;
        let Reply::Receipt(closed) = closed else {
            return Err("close receipt".into());
        };
        let leader = owner.clone();
        let member_id = started.created_ids[0].clone();
        let release = stored(&store, move |store| {
            store.execute(
                &leader,
                &Command::ReleaseHistory(ReleaseHistory {
                    change: Change {
                        pool_id,
                        expected_revision: closed.revision,
                        request_key: "release".into(),
                    },
                    member_id,
                }),
            )
        })
        .await?;
        let Reply::Receipt(release) = release else {
            return Err("release receipt".into());
        };
        let release_id = release.created_id.ok_or("release ID")?;
        let release = loop {
            let item = stored(&store, |store| store.next_effect())
                .await?
                .ok_or("release effect missing")?;
            if item.effect_id == release_id {
                break item;
            }
        };
        effect(&store, &config, release, false).await?;
        let pending = stored(&store, |store| store.pending_unknown()).await?;
        assert!(!pending.iter().any(|item| item.effect_id == release_id));
        let db = rusqlite::Connection::open_with_flags(
            home.join("state.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let pin = pins_by_member
            .get(&started.created_ids[0])
            .ok_or("member pin")?;
        let released: i64 = db.query_row(
            "SELECT released FROM history_pins WHERE pin_id=?1",
            [pin],
            |row| row.get(0),
        )?;
        assert_eq!(released, 1);
        Ok(())
    }

    /// Exercises conditioned replacement through a task-owned Run broker and fake engine.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires a fresh task-owned synthetic Run broker, fake engine and Pool MCP catalog"]
    async fn live_synthetic_pool_replacement() -> Result<(), Box<dyn std::error::Error>> {
        use crate::domain::{CancelReplacement, Change, Create, Replace, Start};
        use serde_json::json;
        let root = fs::canonicalize(std::env::var_os("TMPDIR").ok_or("task TMPDIR required")?)?;
        let home = fs::canonicalize(
            std::env::var_os("AGENT_POOL_SYNTHETIC_RUN_HOME").ok_or("fixture home required")?,
        )?;
        if home == root
            || !home.starts_with(&root)
            || fs::read_to_string(home.join(".pool-synthetic-run"))?
                != "agent-pool synthetic fixture\n"
        {
            return Err("refusing non-fixture Run home".into());
        }
        let expected_engine = fs::canonicalize(
            std::env::var_os("AGENT_POOL_SYNTHETIC_RUN_FIXTURE_BINARY")
                .ok_or("fake engine required")?,
        )?;
        let settings: toml::Value = toml::from_str(&fs::read_to_string(home.join("config.toml"))?)?;
        let engine = settings["harnesses"]["claude-code"]["binary"]
            .as_str()
            .ok_or("engine config")?;
        if fs::canonicalize(engine)? != expected_engine
            || settings["providers"]["glm-user"]["harness"].as_str() != Some("claude-code")
            || settings["mcp"]["agent-pool"]["command"].as_str() != Some("/bin/true")
            || settings["mcp"]["agent-pool"]["global"].as_bool() != Some(true)
        {
            return Err("fixture configuration does not select the fake engine and MCP".into());
        }
        let db = rusqlite::Connection::open_with_flags(
            home.join("state.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        for table in ["agents", "attempts", "start_batch_receipts", "history_pins"] {
            let count: i64 = db.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })?;
            if count != 0 {
                return Err("fixture Run database is not empty".into());
            }
        }
        drop(db);
        let pool_root = home.join("replacement-state");
        fs::create_dir(&pool_root)?;
        fs::set_permissions(&pool_root, fs::Permissions::from_mode(0o700))?;
        let config = Config {
            socket_path: pool_root.join("pool.sock"),
            database_path: pool_root.join("pool.db"),
            expected_uid: fs::metadata(&pool_root)?.uid(),
            bridge_registration_socket: pool_root.join("absent-register"),
            bridge_core_socket: pool_root.join("absent-bridge"),
            bridge_credential_file: pool_root.join("absent-token"),
            bridge_producer_id: "fixture".into(),
            bridge_audience: "fixture".into(),
            bridge_observer_socket: None,
            bridge_observer_credential_file: None,
            owner_observer_credential_file: None,
            run_socket: Some(home.join("api.sock")),
            run_peer_uid: None,
        };
        let mut initial = Store::open(&config.database_path)?;
        let owner = Actor::verified("local/codex/main/owner".into(), "owner", "root")?;
        let Reply::Receipt(created) = initial.execute(
            &owner,
            &Command::Create(Create {
                request_key: "create".into(),
                name: "Fixture".into(),
                purpose: "Replacement".into(),
                acceptance: None,
            }),
        )?
        else {
            return Err("create receipt".into());
        };
        let pool_id = created.pool_id.clone();
        let Reply::Receipt(started) = initial.execute(&owner, &Command::Start(Start {
            change: Change { pool_id: pool_id.clone(), expected_revision: created.revision, request_key: "start".into() },
            name: "Original".into(), role: "Tester".into(), task: "Verify".into(),
            spec: json!({"provider":"glm-user","model":"fixture","profile":"review","explicit_finish":false,"task":"fixture:answer","workdir":home}),
        }))? else { return Err("start receipt".into()) };
        let old_id = started.created_id.clone().ok_or("old member")?;
        let start = initial.next_effect()?.ok_or("start effect")?;
        let start_id = start.effect_id.clone();
        let store = Arc::new(Mutex::new(initial));
        effect(&store, &config, start, false).await?;
        if stored(&store, |store| store.pending_unknown())
            .await?
            .iter()
            .any(|item| item.effect_id == start_id)
        {
            return Err("initial Run admission unresolved".into());
        }
        let pool = pool_id.clone();
        let member = old_id.clone();
        let binding = stored(&store, move |store| {
            store.run_proof_binding(&pool, &member, None)
        })
        .await?;
        let old = &binding.binding;
        let expected_store = old.run_store_id.clone().ok_or("store ID")?;
        let target = crate::run_status::Target {
            agent_id: old.run_id.clone().ok_or("Run ID")?,
            sequence: u32::try_from(old.run_sequence.ok_or("sequence")?)?,
            execution_ref: old.run_execution_ref.clone().ok_or("execution ref")?,
            pin_id: old.run_pin_id.clone().ok_or("pin")?,
        };
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if integrations::run_status(&config, &expected_store, std::slice::from_ref(&target))
                    .await
                    .is_ok_and(|snapshot| {
                        snapshot
                            .items()
                            .any(|item| item.replacement_precondition().is_some())
                    })
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await?;
        // Resume the original lineage once so replacement must select its proven latest incarnation.
        let socket = config.run_socket.as_ref().ok_or("Run socket")?;
        private_socket(socket, config.expected_uid)?;
        let mut stream = UnixStream::connect(socket).await?;
        if stream.peer_cred()?.uid() != config.expected_uid {
            return Err("fixture Run peer mismatch".into());
        }
        let mut bytes = serde_json::to_vec(&json!({
            "jsonrpc":"2.0", "id":7, "method":"resume", "params":{
                "agent_id":target.agent_id, "task":"fixture:answer", "request_id":"pool-fixture-resume"
            }
        }))?;
        bytes.push(b'\n');
        stream.write_all(&bytes).await?;
        let reply: serde_json::Value =
            serde_json::from_slice(&integrations::read_frame(&mut stream).await?)?;
        if reply["id"] != 7 || reply.get("error").is_some() || reply["result"]["sequence"] != 2 {
            return Err("fixture resume was not confirmed".into());
        }
        let latest = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if let Ok(snapshot) = integrations::run_status(
                    &config,
                    &expected_store,
                    std::slice::from_ref(&target),
                )
                .await
                    && let Some(condition) = snapshot
                        .items()
                        .find_map(|item| item.replacement_precondition())
                    && condition.sequence == 2
                {
                    return condition;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await?;
        assert_eq!(latest.agent_id, target.agent_id);
        assert_eq!(latest.pin_id, target.pin_id);
        assert_ne!(latest.execution_ref, target.execution_ref);
        let command = Command::Replace(Replace {
            change: Change {
                pool_id: pool_id.clone(),
                expected_revision: started.revision,
                request_key: "replace".into(),
            },
            member_id: old_id.clone(),
            spec: None,
        });
        let leader = owner.clone();
        let request = command.clone();
        let Reply::Receipt(requested) =
            stored(&store, move |store| store.execute(&leader, &request)).await?
        else {
            return Err("replacement receipt".into());
        };
        let effect_id = requested
            .created_id
            .clone()
            .ok_or("replacement effect ID")?;
        let new_id = requested.created_ids.first().ok_or("new member")?.clone();
        let next = stored(&store, |store| store.next_effect())
            .await?
            .ok_or("replacement effect")?;
        assert_eq!(next.effect_id, effect_id);
        effect(&store, &config, next, false).await?;
        if stored(&store, |store| store.pending_unknown())
            .await?
            .iter()
            .any(|item| item.effect_id == effect_id)
        {
            return Err("replacement Run admission unresolved".into());
        }
        let pool = pool_id.clone();
        let member = new_id.clone();
        let new = stored(&store, move |store| {
            store.run_proof_binding(&pool, &member, None)
        })
        .await?;
        let replacement_revision = new.revision;
        assert!(new.current);
        assert_ne!(
            new.binding.run_id.as_deref(),
            Some(target.agent_id.as_str())
        );
        assert_ne!(
            new.binding.run_execution_ref.as_deref(),
            Some(target.execution_ref.as_str())
        );
        assert_ne!(
            new.binding.run_pin_id.as_deref(),
            Some(target.pin_id.as_str())
        );
        assert_eq!(
            new.binding.run_store_id.as_deref(),
            Some(expected_store.as_str())
        );
        let id = effect_id.clone();
        let (_, old_current) = stored(&store, move |store| store.effect_binding(&id))
            .await?
            .ok_or("old binding")?;
        assert!(!old_current);
        let leader = owner.clone();
        let replay = command.clone();
        let reply = stored(&store, move |store| store.execute(&leader, &replay)).await?;
        assert_eq!(
            serde_json::to_value(reply)?,
            serde_json::to_value(Reply::Receipt(requested))?
        );
        let new_target = crate::run_status::Target {
            agent_id: new.binding.run_id.ok_or("new Run ID")?,
            sequence: u32::try_from(new.binding.run_sequence.ok_or("new sequence")?)?,
            execution_ref: new.binding.run_execution_ref.ok_or("new ref")?,
            pin_id: new.binding.run_pin_id.ok_or("new pin")?,
        };
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if integrations::run_status(
                    &config,
                    &expected_store,
                    std::slice::from_ref(&new_target),
                )
                .await
                .is_ok_and(|snapshot| {
                    snapshot
                        .items()
                        .all(|item| item.proves_historical_success())
                }) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await?;
        // Both negative outcomes must reject the entire two-job batch before admission.
        let counts = || -> Result<(i64, i64, i64), rusqlite::Error> {
            let db = rusqlite::Connection::open_with_flags(
                home.join("state.db"),
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )?;
            Ok((
                db.query_row("SELECT COUNT(*) FROM agents", [], |row| row.get(0))?,
                db.query_row("SELECT COUNT(*) FROM start_batch_receipts", [], |row| {
                    row.get(0)
                })?,
                db.query_row("SELECT COUNT(*) FROM history_pins", [], |row| row.get(0))?,
            ))
        };
        assert_eq!(counts()?, (3, 2, 2));
        let jobs: Vec<_> = ["first", "second"].into_iter().map(|name| crate::domain::BatchJob {
            member_id: format!("fixture-{name}"),
            spec: json!({"provider":"glm-user","model":"fixture","profile":"review","explicit_finish":false,"task":"fixture:answer","workdir":home}),
            original_spec: None,
        }).collect();
        let mut mismatch = latest.clone();
        mismatch.execution_ref = format!(
            "ex1_{}",
            if latest.execution_ref.ends_with('f') {
                "e".repeat(64)
            } else {
                "f".repeat(64)
            }
        );
        let not_met = [new_target.clone(), mismatch];
        let error = integrations::start_batch_with_preconditions(
            &config,
            "pool-fixture-not-met",
            &jobs,
            true,
            &expected_store,
            &not_met,
        )
        .await
        .err()
        .ok_or("mismatched precondition admitted jobs")?;
        assert_eq!(error.code, "PreconditionFailed");
        assert_eq!(error.precondition_reason, Some("not_met"));
        assert_eq!(counts()?, (3, 2, 2));
        let mut missing = latest.clone();
        missing.agent_id = "ag-20000101-000000-ffffffffff".into();
        let unknown = [new_target.clone(), missing];
        let error = integrations::start_batch_with_preconditions(
            &config,
            "pool-fixture-unknown",
            &jobs,
            true,
            &expected_store,
            &unknown,
        )
        .await
        .err()
        .ok_or("unknown precondition admitted jobs")?;
        assert_eq!(error.code, "PreconditionFailed");
        assert_eq!(error.precondition_reason, Some("unknown"));
        assert_eq!(counts()?, (3, 2, 2));
        // A successful ordered batch and its lookup/replay preserve the exact same identities.
        let conditions = [new_target.clone(), latest];
        let first = integrations::start_batch_with_preconditions(
            &config,
            "pool-fixture-ordered",
            &jobs,
            true,
            &expected_store,
            &conditions,
        )
        .await
        .map_err(|error| format!("ordered batch: {error:?}"))?;
        let replay = integrations::start_batch_with_preconditions(
            &config,
            "pool-fixture-ordered",
            &jobs,
            true,
            &expected_store,
            &conditions,
        )
        .await
        .map_err(|error| format!("ordered replay: {error:?}"))?;
        let lookup = integrations::batch_receipt_with_preconditions(
            &config,
            "pool-fixture-ordered",
            &jobs,
            true,
            &expected_store,
            &conditions,
        )
        .await
        .map_err(|error| format!("ordered lookup: {error:?}"))?
        .ok_or("missing ordered receipt")?;
        let identities = |entries: &[integrations::BatchAdmission]| {
            entries
                .iter()
                .map(|entry| {
                    (
                        entry.agent_id.clone(),
                        entry.sequence,
                        entry.execution_ref.clone(),
                        entry.pin_id.clone(),
                    )
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(identities(&first), identities(&replay));
        assert_eq!(identities(&first), identities(&lookup));
        let mut reversed = conditions.clone();
        reversed.reverse();
        assert!(
            integrations::batch_receipt_with_preconditions(
                &config,
                "pool-fixture-ordered",
                &jobs,
                true,
                &expected_store,
                &reversed
            )
            .await
            .is_err()
        );
        let targets: Vec<_> = first
            .into_iter()
            .map(|entry| {
                Ok(crate::run_status::Target {
                    agent_id: entry.agent_id,
                    sequence: u32::try_from(entry.sequence)?,
                    execution_ref: entry.execution_ref,
                    pin_id: entry.pin_id.ok_or("probe pin")?,
                })
            })
            .collect::<Result<_, Box<dyn std::error::Error>>>()?;
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if integrations::run_status(&config, &expected_store, &targets)
                    .await
                    .is_ok_and(|snapshot| {
                        snapshot
                            .items()
                            .all(|item| item.proves_historical_success())
                    })
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await?;
        let db = rusqlite::Connection::open_with_flags(
            home.join("state.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        for (table, expected) in [
            ("agents", 5),
            ("start_batch_receipts", 3),
            ("history_pins", 4),
        ] {
            let count: i64 = db.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })?;
            assert_eq!(count, expected, "{table}");
        }
        let active: i64 = db.query_row(
            "SELECT COUNT(*) FROM attempts WHERE ownership_active=1",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(active, 0);
        drop(db);

        // A second replacement cancelled before dispatch must not admit another Run job.
        let cancel_member = new_id.clone();
        let cancel_pool = pool_id.clone();
        let leader = owner.clone();
        let Reply::Receipt(pending) = stored(&store, move |store| {
            store.execute(
                &leader,
                &Command::Replace(Replace {
                    change: Change {
                        pool_id: cancel_pool,
                        expected_revision: replacement_revision,
                        request_key: "prepare-cancel".into(),
                    },
                    member_id: cancel_member,
                    spec: None,
                }),
            )
        })
        .await?
        else {
            return Err("second replacement receipt".into());
        };
        let cancelled_id = pending.created_id.clone().ok_or("cancelled operation")?;
        let cancel_pool = pool_id.clone();
        let cancel_operation = cancelled_id.clone();
        let leader = owner.clone();
        let Reply::Receipt(cancelled) = stored(&store, move |store| {
            store.execute(
                &leader,
                &Command::CancelReplacement(CancelReplacement {
                    change: Change {
                        pool_id: cancel_pool,
                        expected_revision: pending.revision,
                        request_key: "cancel-unsubmitted".into(),
                    },
                    operation_id: cancel_operation,
                }),
            )
        })
        .await?
        else {
            return Err("cancellation receipt".into());
        };
        assert_eq!(counts()?, (5, 3, 4));
        let request: crate::observer::Request = serde_json::from_value(json!({
            "schema_version":1,"operation":"get","params":{"pool_id":pool_id,"section":"deliveries"}
        }))?;
        let crate::observer::Data::Detail(detail) =
            stored(&store, move |store| store.observe(&request)).await?
        else {
            return Err("delivery projection".into());
        };
        let view = detail.view.ok_or("delivery view")?;
        assert!(
            view.deliveries
                .iter()
                .any(|item| item.operation_id == effect_id
                    && item.operation == "replace"
                    && item.state == "accepted"
                    && item.member_id.as_deref() == Some(old_id.as_str()))
        );
        assert!(
            view.deliveries
                .iter()
                .any(|item| item.operation_id == cancelled_id
                    && item.operation == "replace"
                    && item.state == "cancelled"
                    && item.member_id.as_deref() == Some(new_id.as_str()))
        );
        eprintln!(
            "synthetic fixture: pool={pool_id} current_member={new_id} old_member={old_id} accepted_operation={effect_id} cancelled_operation={cancelled_id} revision={}",
            cancelled.revision
        );
        Ok(())
    }

    /// Exchanges one request through the production connection dispatcher on an isolated Unix pair.
    /// Both futures are joined under a deadline; no resident worker or provider is started.
    async fn observer_exchange(
        config: &Config,
        store: &SharedStore,
        value: serde_json::Value,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let (server, mut client) = UnixStream::pair()?;
        let (_stop, stopped) = watch::channel(false);
        let exchange = async {
            let mut bytes = serde_json::to_vec(&value)?;
            bytes.push(b'\n');
            client.write_all(&bytes).await?;
            let response = integrations::read_frame(&mut client).await?;
            Ok::<_, Box<dyn std::error::Error>>(serde_json::from_slice(&response)?)
        };
        let (server, response) = tokio::time::timeout(Duration::from_secs(3), async {
            tokio::join!(
                connection(
                    server,
                    config.clone(),
                    Arc::clone(store),
                    Arc::new(Semaphore::new(MAX_WAITERS)),
                    stopped
                ),
                exchange
            )
        })
        .await?;
        server?;
        response
    }

    /// The effective transport accepts only authenticated owner projections and refuses all native/admin paths.
    /// Native requests still require assertions; fixture endpoints do not exist, and DB/WAL remain unchanged.
    #[tokio::test]
    async fn observer_socket_authority_is_separate_and_read_only()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory =
            tempfile::tempdir_in(std::env::var_os("TMPDIR").ok_or("task TMPDIR required")?)?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let path = directory.path();
        let token = path.join("observer.token");
        fs::write(&token, "fixture-owner-observer")?;
        fs::set_permissions(&token, fs::Permissions::from_mode(0o600))?;
        let mut config = Config {
            socket_path: path.join("pool.sock"),
            database_path: path.join("pool.db"),
            expected_uid: fs::metadata(path)?.uid(),
            bridge_registration_socket: path.join("absent-registration.sock"),
            bridge_core_socket: path.join("absent-core.sock"),
            bridge_credential_file: path.join("absent-producer.token"),
            bridge_producer_id: "fixture".into(),
            bridge_audience: "fixture".into(),
            bridge_observer_socket: None,
            bridge_observer_credential_file: None,
            owner_observer_credential_file: Some(token),
            run_socket: None,
            run_peer_uid: None,
        };
        let mut initial = Store::open(&config.database_path)?;
        let actor = Actor::verified("codex:test:observer:owner".into(), "owner", "root")?;
        let reply = initial.execute(
            &actor,
            &Command::Create(crate::domain::Create {
                request_key: "fixture-create".into(),
                name: "Fixture".into(),
                purpose: "Read-only observation".into(),
                acceptance: None,
            }),
        )?;
        let Reply::Receipt(receipt) = reply else {
            return Err("fixture receipt".into());
        };
        let store = Arc::new(Mutex::new(initial));
        let db_before = fs::read(&config.database_path)?;
        let wal = config.database_path.with_file_name("pool.db-wal");
        let wal_before = fs::read(&wal)?;
        let identity = serde_json::json!({"schema_version":1,"operation":"identity","params":{}});
        for observe in [
            identity.clone(),
            serde_json::json!({"schema_version":1,"operation":"list","params":{}}),
            serde_json::json!({"schema_version":1,"operation":"get","params":{"pool_id":receipt.pool_id}}),
        ] {
            let response = observer_exchange(&config, &store, serde_json::json!({"observer_credential":"fixture-owner-observer","observe":observe})).await?;
            assert!(
                response.get("error").is_none(),
                "authorized read must succeed: {response}"
            );
            assert!(response.get("data").is_some());
            assert!(!response.to_string().contains("fixture-owner-observer"));
        }
        for credential in ["", "wrong", "native-assertion-secret"] {
            let response = observer_exchange(
                &config,
                &store,
                serde_json::json!({"observer_credential":credential,"observe":identity}),
            )
            .await?;
            assert_eq!(response["error"]["code"], "unauthorized");
        }
        let response =
            observer_exchange(&config, &store, serde_json::json!({"observe":identity})).await?;
        assert_eq!(response["error"]["code"], "invalid");
        let saved = config.owner_observer_credential_file.take();
        let response = observer_exchange(
            &config,
            &store,
            serde_json::json!({"observer_credential":"fixture-owner-observer","observe":identity}),
        )
        .await?;
        assert_eq!(response["error"]["code"], "unauthorized");
        config.owner_observer_credential_file = saved;
        for name in crate::tools::definitions()
            .iter()
            .filter_map(|tool| tool["name"].as_str())
            .chain(["replay", "admin", "claim", "settle"])
        {
            for value in [
                serde_json::json!({"observer_credential":"fixture-owner-observer","observe":{"schema_version":1,"operation":name,"params":{}}}),
                serde_json::json!({"observer_credential":"fixture-owner-observer","observe":identity,"command":{"name":name,"arguments":{}},"assertion":{"assertion_key":"fixture-owner-observer","invocation_key":"reused"}}),
            ] {
                let response = observer_exchange(&config, &store, value).await?;
                assert_eq!(
                    response["error"]["code"], "invalid",
                    "observer must refuse {name}"
                );
                assert!(response.get("data").is_none());
            }
        }
        let response = observer_exchange(
            &config,
            &store,
            serde_json::json!({"command":{"name":"pool_list","arguments":{}}}),
        )
        .await?;
        assert_eq!(response["Err"], "invalid");
        let response = observer_exchange(&config, &store, serde_json::json!({"assertion":{"assertion_key":"fixture-owner-observer","invocation_key":"reused"},"command":{"name":"pool_list","arguments":{}}})).await?;
        assert_eq!(response["Err"], "unavailable");
        assert_eq!(fs::read(&config.database_path)?, db_before);
        assert_eq!(fs::read(&wal)?, wal_before);
        Ok(())
    }

    /// Owner proof is read-only, correlated to the binding, and fenced by Pool revision.
    #[tokio::test]
    async fn owner_run_proof_observes_binding_without_authorizing_and_rechecks_revision()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::domain::{Add, Change, Create, Start, Update};
        use serde_json::{Value, json};
        let directory =
            tempfile::tempdir_in(std::env::var_os("TMPDIR").ok_or("task TMPDIR required")?)?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let path = directory.path();
        let token = path.join("observer.token");
        fs::write(&token, "fixture-owner-observer")?;
        fs::set_permissions(&token, fs::Permissions::from_mode(0o600))?;
        let config = Config {
            socket_path: path.join("pool.sock"),
            database_path: path.join("pool.db"),
            expected_uid: fs::metadata(path)?.uid(),
            bridge_registration_socket: path.join("absent-registration.sock"),
            bridge_core_socket: path.join("absent-core.sock"),
            bridge_credential_file: path.join("absent-token"),
            bridge_producer_id: "fixture".into(),
            bridge_audience: "fixture".into(),
            bridge_observer_socket: None,
            bridge_observer_credential_file: None,
            owner_observer_credential_file: Some(token),
            run_socket: Some(path.join("run.sock")),
            run_peer_uid: None,
        };
        let socket = config.run_socket.as_ref().ok_or("missing Run socket")?;
        let listener = UnixListener::bind(socket)?;
        fs::set_permissions(socket, fs::Permissions::from_mode(0o600))?;
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/fixtures/run-status-v1-success.json"))?;
        let target: crate::run_status::Target =
            serde_json::from_value(fixture["socket"]["request"]["targets"][0].clone())?;
        let store_id = fixture["socket"]["request"]["expected_store_id"]
            .as_str()
            .ok_or("missing store")?
            .to_owned();
        let mut run_result = fixture["socket"]["result"].clone();
        run_result.as_object_mut().ok_or("result")?.remove("view");
        let mut initial = Store::open(&config.database_path)?;
        let owner = Actor::verified("local/codex/main/owner".into(), "owner", "root")?;
        let Reply::Receipt(created) = initial.execute(
            &owner,
            &Command::Create(Create {
                request_key: "create".into(),
                name: "Fixture".into(),
                purpose: "Proof observation".into(),
                acceptance: None,
            }),
        )?
        else {
            return Err("missing create receipt".into());
        };
        let Reply::Receipt(started) = initial.execute(
            &owner,
            &Command::Start(Start {
                change: Change {
                    pool_id: created.pool_id.clone(),
                    expected_revision: created.revision,
                    request_key: "start".into(),
                },
                name: "Run member".into(),
                role: "Tester".into(),
                task: "Verify".into(),
                spec: json!({"task":"Verify","provider":"fixture"}),
            }),
        )?
        else {
            return Err("missing start receipt".into());
        };
        let member = started.created_id.clone().ok_or("missing member")?;
        let admitted = initial.next_effect()?.ok_or("missing admission")?;
        let route = configured_run_route(&config)?;
        assert!(initial.freeze_run_route(&admitted.effect_id, &route, false)?);
        initial.record_run_store_id(&admitted.effect_id, &store_id)?;
        initial.record_batch_admission(
            &admitted.effect_id,
            Some(&store_id),
            &[(
                target.agent_id.clone(),
                u64::from(target.sequence),
                target.execution_ref.clone(),
                Some(target.pin_id.clone()),
            )],
        )?;
        let Reply::Receipt(added) = initial.execute(
            &owner,
            &Command::Add(Add {
                change: Change {
                    pool_id: created.pool_id.clone(),
                    expected_revision: started.revision,
                    request_key: "add".into(),
                },
                address: "local/codex/main/bridge-member".into(),
                name: "Bridge member".into(),
                role: "Tester".into(),
                task: "Verify".into(),
            }),
        )?
        else {
            return Err("missing add receipt".into());
        };
        let revision = added.revision;
        let unbound = added.created_id.ok_or("missing unbound member")?;
        let store = Arc::new(Mutex::new(initial));
        let request = |member_id: &str, credential: &str| {
            json!({
                "observer_credential":credential,
                "observe":{"schema_version":1,"operation":"get","params":{
                    "pool_id":created.pool_id,"section":"run_proof","member_id":member_id,
                "expected_revision":revision
                }}
            })
        };
        let denied = observer_exchange(&config, &store, request(&member, "wrong")).await?;
        assert_eq!(denied["error"]["code"], "unauthorized");
        let unknown =
            observer_exchange(&config, &store, request(&unbound, "fixture-owner-observer")).await?;
        assert_eq!(unknown["kind"], "run_proof");
        assert_eq!(unknown["data"]["state"], "unknown");
        assert_eq!(unknown["data"]["reason"], "incomplete_binding");
        assert_eq!(unknown["data"]["author_identity"], "unknown");
        assert!(unknown["data"].get("proof").is_none());
        let mut drift = config.clone();
        drift.run_socket = Some(path.join("different.sock"));
        let unknown =
            observer_exchange(&drift, &store, request(&member, "fixture-owner-observer")).await?;
        assert_eq!(unknown["data"]["reason"], "origin_unavailable");
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
        let db_before = fs::read(&config.database_path)?;
        let wal = config.database_path.with_file_name("pool.db-wal");
        let wal_before = fs::read(&wal)?;
        let (observed, served) = tokio::join!(
            observer_exchange(&config, &store, request(&member, "fixture-owner-observer")),
            async {
                let (stream, request) = receive_run_request(&listener).await?;
                assert_eq!(request["method"], "status");
                assert_eq!(request["params"]["expected_store_id"], store_id);
                assert_eq!(request["params"]["targets"], json!([target]));
                reply_to_run_request(stream, &request, run_result.clone()).await
            }
        );
        served?;
        let observed = observed?;
        assert_eq!(observed["kind"], "run_proof");
        assert_eq!(observed["data"]["state"], "observed");
        assert_eq!(observed["data"]["pool_revision"], revision);
        assert_eq!(observed["data"]["author_identity"], "unknown");
        assert_eq!(observed["data"]["proof"]["status"]["match"], "verified");
        assert_eq!(
            observed["data"]["proof"]["outcome_scope"],
            "retained_latest"
        );
        assert_eq!(observed["data"]["proof"]["historical_success"], true);
        assert!(observed["data"]["run_observed_at"].as_f64().is_some());
        assert!(observed["data"]["observed_at_unix_ms"].as_u64().is_some());
        let decoded: crate::observer::Envelope = serde_json::from_value(observed)?;
        assert!(matches!(
            decoded.data,
            Some(crate::observer::Data::RunProof(_))
        ));

        let examples: Value =
            serde_json::from_str(include_str!("../tests/fixtures/run-status-v1.json"))?;
        for (case_name, restart) in [
            ("verified_selected_not_tail", "none"),
            ("restart_pending_raw_terminal", "pending"),
        ] {
            let mut result = examples["cases"][case_name]["response"]["result"].clone();
            result["store_id"] = json!(store_id);
            result.as_object_mut().ok_or("result")?.remove("view");
            let item = &mut result["items"][0];
            item["selector"] = serde_json::to_value(&target)?;
            item["canonical_agent_id"] = json!(target.agent_id);
            item["pin_id"] = json!(target.pin_id);
            item["selected"]["execution_ref"] = json!(target.execution_ref);
            let (observed, served) = tokio::join!(
                observer_exchange(&config, &store, request(&member, "fixture-owner-observer")),
                async {
                    let (stream, request) = receive_run_request(&listener).await?;
                    reply_to_run_request(stream, &request, result).await
                }
            );
            served?;
            let observed = observed?;
            assert_eq!(observed["data"]["state"], "observed");
            assert_eq!(
                observed["data"]["proof"]["status"]["selected"]["raw_status"],
                "succeeded"
            );
            assert_eq!(
                observed["data"]["proof"]["status"]["retained_latest"]["sequence"],
                2
            );
            assert_eq!(
                observed["data"]["proof"]["status"]["restart_resume"],
                restart
            );
            assert_eq!(observed["data"]["proof"]["historical_success"], false);
        }

        let mut mismatch = run_result.clone();
        let item = &mut mismatch["items"][0];
        item["match"] = json!("mismatch");
        item["selected"] = Value::Null;
        item["retained_latest"] = Value::Null;
        item["coverage"] = json!("unknown");
        item["restart_resume"] = json!("unknown");
        item["lineage_terminal"] = Value::Null;
        item["terminal_outcome"] = Value::Null;
        item["success_commit"] = json!("unknown");
        item["cleanup"]["state"] = json!("unknown");
        let (observed, served) = tokio::join!(
            observer_exchange(&config, &store, request(&member, "fixture-owner-observer")),
            async {
                let (stream, request) = receive_run_request(&listener).await?;
                reply_to_run_request(stream, &request, mismatch).await
            }
        );
        served?;
        let observed = observed?;
        assert_eq!(observed["data"]["proof"]["status"]["match"], "mismatch");
        assert_eq!(observed["data"]["proof"]["historical_success"], false);
        let mut wrong_store = run_result.clone();
        wrong_store["store_id"] = json!(format!("store_{}", "f".repeat(32)));
        let (unknown, served) = tokio::join!(
            observer_exchange(&config, &store, request(&member, "fixture-owner-observer")),
            async {
                let (stream, request) = receive_run_request(&listener).await?;
                reply_to_run_request(stream, &request, wrong_store).await
            }
        );
        served?;
        let unknown = unknown?;
        assert_eq!(unknown["data"]["state"], "unknown");
        assert_eq!(unknown["data"]["reason"], "run_unavailable");
        assert!(unknown["data"].get("proof").is_none());
        let (unknown, served) = tokio::join!(
            observer_exchange(&config, &store, request(&member, "fixture-owner-observer")),
            async {
                let (stream, _) = receive_run_request(&listener).await?;
                drop(stream);
                Ok::<_, Box<dyn std::error::Error>>(())
            }
        );
        served?;
        assert_eq!(unknown?["data"]["reason"], "run_unavailable");
        assert_eq!(fs::read(&config.database_path)?, db_before);
        assert_eq!(fs::read(&wal)?, wal_before);

        // Binding resolution can commit without bumping the public pool revision.
        // The original Run result must still be rejected when that binding changed.
        let admission_id = admitted.effect_id.clone();
        let (stale_binding, served) = tokio::join!(
            observer_exchange(&config, &store, request(&member, "fixture-owner-observer")),
            async {
                let (stream, request) = receive_run_request(&listener).await?;
                stored(&store, move |store| {
                    store.bind_run(&admission_id, "local/codex/main/new-run-address")
                })
                .await?;
                reply_to_run_request(stream, &request, run_result.clone()).await
            }
        );
        served?;
        assert_eq!(stale_binding?["error"]["code"], "stale");
        let pool_for_binding = created.pool_id.clone();
        let member_for_binding = member.clone();
        let after = stored(&store, move |store| {
            store.run_proof_binding(&pool_for_binding, &member_for_binding, None)
        })
        .await?;
        assert_eq!(after.revision, revision);
        assert_eq!(
            after.binding.address.as_deref(),
            Some("local/codex/main/new-run-address")
        );

        let pool = created.pool_id.clone();
        let owner_for_update = owner.clone();
        let (stale, served) = tokio::join!(
            observer_exchange(&config, &store, request(&member, "fixture-owner-observer")),
            async {
                let (stream, request) = receive_run_request(&listener).await?;
                stored(&store, move |store| {
                    store.execute(
                        &owner_for_update,
                        &Command::Update(Update {
                            change: Change {
                                pool_id: pool,
                                expected_revision: revision,
                                request_key: "update".into(),
                            },
                            name: "Changed".into(),
                            purpose: "Changed".into(),
                        }),
                    )
                })
                .await?;
                reply_to_run_request(stream, &request, run_result).await
            }
        );
        served?;
        assert_eq!(stale?["error"]["code"], "stale");
        Ok(())
    }

    /// A poisoned writer never authorizes later work; blocking failure is observed as Internal.
    #[tokio::test]
    async fn blocking_writer_panic_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let directory =
            tempfile::tempdir_in(std::env::var_os("TMPDIR").ok_or("task TMPDIR required")?)?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let store = Arc::new(Mutex::new(Store::open(&directory.path().join("pool.db"))?));
        let outcome: Result<(), Fault> =
            stored(&store, |_store| panic!("fixture writer panic")).await;
        assert_eq!(outcome, Err(Fault::Internal));
        let outcome = stored(&store, |_store| Ok(())).await;
        assert_eq!(outcome, Err(Fault::Internal));
        Ok(())
    }

    /// A requested stop is joined without touching absent providers or changing durable state.
    #[tokio::test]
    async fn stopped_worker_joins_without_starting_provider_effects()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory =
            tempfile::tempdir_in(std::env::var_os("TMPDIR").ok_or("task TMPDIR required")?)?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let store = Arc::new(Mutex::new(Store::open(&directory.path().join("pool.db"))?));
        let config = Config {
            socket_path: directory.path().join("pool.sock"),
            database_path: directory.path().join("pool.db"),
            expected_uid: fs::metadata(directory.path())?.uid(),
            bridge_registration_socket: directory.path().join("absent-bridge.sock"),
            bridge_core_socket: directory.path().join("absent-core.sock"),
            bridge_credential_file: directory.path().join("absent-token"),
            bridge_producer_id: "fixture".into(),
            bridge_audience: "fixture-backend".into(),
            bridge_observer_socket: None,
            bridge_observer_credential_file: None,
            owner_observer_credential_file: None,
            run_socket: None,
            run_peer_uid: None,
        };
        let (stop, stopped) = watch::channel(false);
        stop.send(true)?;
        let mut worker = tokio::spawn(work(config, Arc::clone(&store), stopped));
        match tokio::time::timeout(Duration::from_secs(2), &mut worker).await {
            Ok(result) => result??,
            Err(error) => {
                worker.abort();
                let outcome = worker.await;
                assert!(outcome.is_err_and(|error| error.is_cancelled()));
                return Err(error.into());
            }
        }
        assert!(
            stored(&store, |store| store.pending_unknown())
                .await?
                .is_empty()
        );
        Ok(())
    }
}
