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
    tokio::time::timeout(EXCHANGE_TIMEOUT * 3, async {
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
/// Every replay consumes current native evidence before the store can return a receipt.
async fn connection(
    mut stream: UnixStream,
    config: Config,
    store: SharedStore,
) -> Result<(), Fault> {
    if stream.peer_cred().map_err(|_| Fault::Unauthorized)?.uid() != config.expected_uid {
        return Err(Fault::Unauthorized);
    }
    let result = async {
        let bytes = tokio::time::timeout(EXCHANGE_TIMEOUT, integrations::read_frame(&mut stream))
            .await
            .map_err(|_| Fault::Unavailable)??;
        let request: Request = serde_json::from_slice(&bytes).map_err(|_| Fault::Invalid)?;
        request.command.validate()?;
        let actor = integrations::consume(config.clone(), request.assertion).await?;
        if let Command::Add(add) = &request.command {
            let parsed = bridge_sdk::bridge_protocol::NativeAddress::parse(&add.address)
                .map_err(|_| Fault::Invalid)?;
            if parsed.canonical() != add.address {
                return Err(Fault::Invalid);
            }
        }
        let join_binding = if let Command::Join(change) = &request.command {
            Some(verify_managed_join(&store, &config, &actor, &change.pool_id).await?)
        } else {
            None
        };
        stored(&store, move |store| {
            if let Some(expected) = join_binding {
                return store.execute_join(&actor, &request.command, &expected);
            }
            store.execute(&actor, &request.command)
        })
        .await
    }
    .await;
    let mut bytes = serde_json::to_vec(&result).map_err(|_| Fault::Internal)?;
    if bytes.len() > MAX_FRAME {
        return Err(Fault::Internal);
    }
    bytes.push(b'\n');
    tokio::time::timeout(EXCHANGE_TIMEOUT, stream.write_all(&bytes))
        .await
        .map_err(|_| Fault::Unavailable)?
        .map_err(|_| Fault::Unavailable)
}

/// Rechecks a managed enrollment's exact live Run sequence at join time.
/// A cached address or completed/unsupported execution alone cannot admit a managed member.
async fn verify_managed_join(
    store: &SharedStore,
    config: &Config,
    actor: &Actor,
    pool_id: &str,
) -> Result<Binding, Fault> {
    let caller = actor.clone();
    let pool_id = pool_id.to_owned();
    let target = stored(store, move |store| store.join_binding(&caller, &pool_id)).await?;
    // An existing member can recover the original join receipt after its Run ended;
    // new join intents are still rejected by the domain's already-confirmed guard.
    if target.member.state == crate::domain::MemberState::Active {
        return Ok(target);
    }
    if let (Some(agent_id), Some(sequence)) = (&target.run_id, target.run_sequence) {
        let observation = integrations::run_observe(config, agent_id, sequence).await?;
        if observation.address.as_deref() != Some(&actor.address) {
            return Err(Fault::Unauthorized);
        }
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
    let mut worker = tokio::spawn(work(config.clone(), Arc::clone(&store), stopped));
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
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
                connections.spawn(async move { let _permit = permit; connection(stream, config, store).await });
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
    let state = match &effect.work {
        Work::Deliver { .. } => {
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
        Work::Start { spec, request_key } => {
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
                    _ => integrations::start(config, spec, request_key).await,
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
                    match integrations::run_observe(config, &admission.agent_id, sequence).await {
                        Ok(observation) => match observation.address {
                            Some(address) => {
                                let effect_id = effect.effect_id.clone();
                                match stored(store, move |store| {
                                    store.bind_run(&effect_id, &address)
                                })
                                .await
                                {
                                    Ok(()) => "accepted",
                                    Err(Fault::Conflict | Fault::Forbidden) => "refused",
                                    Err(error) => return Err(error),
                                }
                            }
                            None if matches!(
                                observation.runtime.as_str(),
                                "failed" | "lost" | "cancelled" | "succeeded"
                            ) =>
                            {
                                "unknown"
                            }
                            None => "custody",
                        },
                        Err(_) => "unknown",
                    }
                }
                Err(error) if error.known_unadmitted => {
                    eprintln!("Run admission refused: {}", error.code);
                    "refused"
                }
                Err(_) => "unknown",
            }
        }
    };
    settle(store, effect.effect_id, state).await
}

/// Persists one effect result; storage failure stops the worker rather than claiming delivery.
async fn settle(store: &SharedStore, effect_id: String, state: &'static str) -> Result<(), Fault> {
    stored(store, move |store| store.settle_effect(&effect_id, state)).await
}

/// Samples one current membership through its proper provider; missing data is explicitly unknown.
async fn observation(store: &SharedStore, config: &Config, target: Binding) -> Result<(), Fault> {
    let runtime = match (&target.run_id, target.run_sequence, &target.address) {
        (Some(agent_id), Some(sequence), _) => {
            integrations::run_observe(config, agent_id, sequence)
                .await
                .map(|value| value.runtime)
        }
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
            run_socket: None,
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
