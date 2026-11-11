//! One persistent resident, authenticated one-call frontend and owned serial outbox worker.
use crate::{
    config::{Config, private_file, private_parent, private_socket},
    domain::{Actor, Binding, Command, Effect, Fault, Reply, Work},
    integrations::{self, Assertion, EXCHANGE_TIMEOUT, MAX_FRAME},
    store::{Admitted, Store},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
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

/// A live frontend and recovery must never drive the same durable work at once.
#[derive(Clone, Hash, PartialEq, Eq)]
enum ManagedWork {
    Bootstrap(String),
    Intent(String),
    Egress(String),
    EgressScope(String),
}
#[derive(Default)]
struct ManagedActivity {
    active: Mutex<HashSet<ManagedWork>>,
}
#[derive(Clone)]
struct ManagedLease {
    _inner: Arc<ManagedLeaseInner>,
}
struct ManagedLeaseInner {
    activity: Arc<ManagedActivity>,
    work: ManagedWork,
}
impl Drop for ManagedLeaseInner {
    fn drop(&mut self) {
        if let Ok(mut active) = self.activity.active.lock() {
            active.remove(&self.work);
        }
    }
}
impl ManagedActivity {
    fn acquire(self: &Arc<Self>, work: ManagedWork) -> Result<Option<ManagedLease>, Fault> {
        let mut active = self.active.lock().map_err(|_| Fault::Unavailable)?;
        if active.contains(&work) {
            return Ok(None);
        }
        if active.len() >= MAX_CONNECTIONS * 2 + 2 {
            return Ok(None);
        }
        active.insert(work.clone());
        drop(active);
        Ok(Some(ManagedLease {
            _inner: Arc::new(ManagedLeaseInner {
                activity: Arc::clone(self),
                work,
            }),
        }))
    }
}

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

/// Keep the lease inside a blocking closure even if its async caller is cancelled.
async fn stored_managed<T, F>(
    store: &SharedStore,
    lease: &ManagedLease,
    operation: F,
) -> Result<T, Fault>
where
    T: Send + 'static,
    F: FnOnce(&mut Store) -> Result<T, Fault> + Send + 'static,
{
    let lease = lease.clone();
    stored(store, move |store| {
        let _lease = lease;
        operation(store)
    })
    .await
}

/// Pin both endpoints of the managed local session to this exact loaded Pool build.
async fn verify_managed_peer(stream: &UnixStream, uid: u32) -> Result<(), Fault> {
    let credentials = stream.peer_cred().map_err(|_| Fault::Unauthorized)?;
    let pid = u32::try_from(credentials.pid().ok_or(Fault::Unauthorized)?)
        .map_err(|_| Fault::Unauthorized)?;
    if credentials.uid() != uid || pid == std::process::id() {
        return Err(Fault::Unauthorized);
    }
    tokio::task::spawn_blocking(move || {
        use sha2::Digest;
        use std::sync::OnceLock;
        static SELF_PIN: OnceLock<Result<(PathBuf, String), Fault>> = OnceLock::new();
        let (executable, sha256) = SELF_PIN
            .get_or_init(|| {
                let executable =
                    fs::canonicalize(std::env::current_exe().map_err(|_| Fault::Unavailable)?)
                        .map_err(|_| Fault::Unavailable)?;
                let loaded = fs::metadata("/proc/self/exe").map_err(|_| Fault::Unavailable)?;
                let path = fs::metadata(&executable).map_err(|_| Fault::Unavailable)?;
                if !loaded.is_file()
                    || loaded.len() > 512 * 1024 * 1024
                    || (loaded.dev(), loaded.ino()) != (path.dev(), path.ino())
                {
                    return Err(Fault::Unavailable);
                }
                let bytes = fs::read("/proc/self/exe").map_err(|_| Fault::Unavailable)?;
                let after = fs::metadata("/proc/self/exe").map_err(|_| Fault::Unavailable)?;
                if (
                    loaded.dev(),
                    loaded.ino(),
                    loaded.len(),
                    loaded.mtime(),
                    loaded.mtime_nsec(),
                    loaded.ctime(),
                    loaded.ctime_nsec(),
                ) != (
                    after.dev(),
                    after.ino(),
                    after.len(),
                    after.mtime(),
                    after.mtime_nsec(),
                    after.ctime(),
                    after.ctime_nsec(),
                ) {
                    return Err(Fault::Unavailable);
                }
                Ok((executable, format!("{:x}", sha2::Sha256::digest(bytes))))
            })
            .clone()?;
        let route = crate::managed_state::Route {
            component_store_id: String::new(),
            route_id: String::new(),
            worker_uid: uid,
        };
        let peer = crate::managed_run::RunPeer {
            socket: PathBuf::new(),
            expected_uid: uid,
            executable,
            sha256,
            route: route.clone(),
            pool_route: route.clone(),
            bridge_route: route,
            producer: String::new(),
            recovery_capabilities: Vec::new(),
        };
        crate::managed_run::verify_peer(pid, &peer).map_err(|_| Fault::Unauthorized)
    })
    .await
    .map_err(|_| Fault::Unavailable)?
}

pub(crate) async fn connect_managed_peer(path: &Path, uid: u32) -> Result<UnixStream, Fault> {
    let stream = integrations::connect(path, uid).await?;
    verify_managed_peer(&stream, uid).await?;
    Ok(stream)
}

/// Original-observation bootstrap and admitted-command orchestration.
mod managed_dispatch {
    use super::*;
    use crate::{
        managed_bridge::Consumed,
        managed_run::{
            Admission, ConsensusAuthority, CurrentAuthority, IngressInput, IngressQuery, RunError,
            RunPeer,
        },
        managed_state::{
            AdmissionPlan, ConsensusFence, IntentReservation, PendingConsensus, Route,
            RunAuthority, RunPin, VoterState,
        },
    };
    use std::{future::Future, pin::Pin};

    pub(super) type Response<'a, T, E = Fault> =
        Pin<Box<dyn Future<Output = Result<T, E>> + Send + 'a>>;

    pub(super) trait IngressClient {
        fn current<'a>(
            &'a self,
            query: &'a IngressQuery,
        ) -> Response<'a, CurrentAuthority, RunError>;
    }
    impl IngressClient for RunPeer {
        fn current<'a>(
            &'a self,
            query: &'a IngressQuery,
        ) -> Response<'a, CurrentAuthority, RunError> {
            Box::pin(async move { self.current_ingress(query).await })
        }
    }

    /// Retain the original staged request on early-hook not-ready; no newer
    /// process snapshot or alternate route is substituted during retry.
    pub(super) async fn ingress<C: IngressClient>(
        store: &SharedStore,
        activity: &Arc<ManagedActivity>,
        bootstrap: &ManagedLease,
        bootstrap_id: String,
        pin: RunPin,
        input: IngressInput,
        client: &C,
    ) -> Result<CurrentAuthority, Fault> {
        if !Arc::ptr_eq(&bootstrap._inner.activity, activity)
            || bootstrap._inner.work != ManagedWork::Bootstrap(bootstrap_id.clone())
        {
            return Err(Fault::Unauthorized);
        }
        let request_id = input.request_id.clone();
        let query = stored_managed(store, bootstrap, move |store| {
            store.managed_stage_ingress(&bootstrap_id, &pin, input)
        })
        .await?;
        let authority = tokio::time::timeout(EXCHANGE_TIMEOUT, async {
            loop {
                match client.current(&query).await {
                    Ok(authority) => break Ok(authority),
                    Err(RunError::NotReady) => tokio::time::sleep(Duration::from_millis(250)).await,
                    Err(_) => break Err(Fault::Unavailable),
                }
            }
        })
        .await
        .map_err(|_| Fault::Unavailable)??;
        stored_managed(store, bootstrap, move |store| {
            store.managed_record_current(&request_id, &authority)?;
            Ok(authority)
        })
        .await
    }

    pub(super) trait Client {
        fn admit<'a>(&'a self, plan: &'a AdmissionPlan) -> Response<'a, Admission, RunError>;
        fn consensus<'a>(
            &'a self,
            pending: PendingConsensus,
            store: &'a SharedStore,
            lease: &'a ManagedLease,
        ) -> Response<'a, ConsensusFence>;
    }

    pub(super) trait SessionClient:
        IngressClient + Client + Clone + Send + Sync + 'static
    {
        fn current_pin<'a>(&'a self) -> Response<'a, RunPin>;
        fn endpoint(&self) -> crate::managed_state::RunEndpointPin;
        fn pool_route(&self) -> Route;
        fn consume(
            &self,
            key: &crate::managed_bridge::ConsumeKey<'_>,
            assertion: &bridge_sdk::bridge_protocol::Secret,
            server: &str,
            command: &Command,
            epoch: &str,
        ) -> Result<Consumed, crate::managed_bridge::BridgeFailure>;
    }

    #[derive(Clone)]
    pub(super) struct LiveSessionClient {
        pub config: Config,
        pub peer: RunPeer,
        pub bridge: crate::managed_bridge::SdkBridge,
    }
    impl IngressClient for LiveSessionClient {
        fn current<'a>(
            &'a self,
            query: &'a IngressQuery,
        ) -> Response<'a, CurrentAuthority, RunError> {
            Box::pin(async move { self.peer.current_ingress(query).await })
        }
    }
    impl Client for LiveSessionClient {
        fn admit<'a>(&'a self, plan: &'a AdmissionPlan) -> Response<'a, Admission, RunError> {
            Box::pin(async move {
                ConfiguredClient {
                    config: &self.config,
                }
                .admit(plan)
                .await
            })
        }
        fn consensus<'a>(
            &'a self,
            pending: PendingConsensus,
            store: &'a SharedStore,
            lease: &'a ManagedLease,
        ) -> Response<'a, ConsensusFence> {
            Box::pin(async move {
                ConfiguredClient {
                    config: &self.config,
                }
                .consensus(pending, store, lease)
                .await
            })
        }
    }
    impl SessionClient for LiveSessionClient {
        fn current_pin<'a>(&'a self) -> Response<'a, RunPin> {
            Box::pin(async move {
                self.peer
                    .current_pin("attempt_current_ingress_v1")
                    .await
                    .map_err(|_| Fault::Unavailable)
            })
        }
        fn endpoint(&self) -> crate::managed_state::RunEndpointPin {
            self.peer.endpoint_pin()
        }
        fn pool_route(&self) -> Route {
            self.peer.pool_route.clone()
        }
        fn consume(
            &self,
            key: &crate::managed_bridge::ConsumeKey<'_>,
            assertion: &bridge_sdk::bridge_protocol::Secret,
            server: &str,
            command: &Command,
            epoch: &str,
        ) -> Result<Consumed, crate::managed_bridge::BridgeFailure> {
            crate::managed_bridge::consume_original(
                &self.bridge,
                key,
                assertion,
                server,
                command,
                epoch,
            )
        }
    }

    /// Uses only the original configured and durably pinned Run routes.
    pub(super) struct ConfiguredClient<'a> {
        pub config: &'a Config,
    }
    impl Client for ConfiguredClient<'_> {
        fn admit<'a>(&'a self, plan: &'a AdmissionPlan) -> Response<'a, Admission, RunError> {
            Box::pin(async move {
                let peer = RunPeer::from_recovery(self.config, &plan.recovery)?;
                peer.admit(
                    &crate::domain::id(),
                    &plan.recovery.intent_id,
                    &plan.recovery.security_digest,
                    &plan.binding,
                    &plan.recovery.consumed_ref,
                )
                .await
            })
        }
        fn consensus<'a>(
            &'a self,
            pending: PendingConsensus,
            store: &'a SharedStore,
            lease: &'a ManagedLease,
        ) -> Response<'a, ConsensusFence> {
            Box::pin(async move {
                let owner = match &lease._inner.work {
                    ManagedWork::Intent(id) if id == pending.intent_id() => id.clone(),
                    _ => return Err(Fault::Unauthorized),
                };
                let voters = pending.voters().to_vec();
                let mut observations = Vec::with_capacity(voters.len());
                for voter in &voters {
                    let peer = RunPeer::from_config(self.config, &voter.binding.pool_store_id)
                        .map_err(|_| Fault::Unavailable)?;
                    if peer.route != voter.binding.run_route {
                        return Err(Fault::Unavailable);
                    }
                    let endpoint = peer.endpoint_pin();
                    stored_managed(store, lease, move |store| {
                        store.managed_require_run_pin(&endpoint)
                    })
                    .await?;
                    let pin = peer
                        .current_pin("attempt_consensus_v1")
                        .await
                        .map_err(|_| Fault::Unavailable)?;
                    let request_id = crate::domain::id();
                    let transport_id = crate::domain::id();
                    let voter = voter.clone();
                    let owner = owner.clone();
                    let query = stored_managed(store, lease, move |store| {
                        store.managed_stage_voter(&pin, &voter, &request_id, &transport_id, &owner)
                    })
                    .await?;
                    observations.push(
                        peer.collect_voters(&[query])
                            .await
                            .map_err(|_| Fault::Unavailable)?,
                    );
                }
                let authority =
                    ConsensusAuthority::combine(observations).map_err(|_| Fault::Unavailable)?;
                let mut rebound = false;
                for voter in &voters {
                    let observation = authority.consensus(
                        &voter.binding.run_route,
                        &voter.attempt,
                        &voter.incarnation,
                    );
                    if !matches!(observation, Ok(ref result) if result.state == VoterState::Superseded)
                    {
                        continue;
                    }
                    let peer = RunPeer::from_config(self.config, &voter.binding.pool_store_id)
                        .map_err(|_| Fault::Unavailable)?;
                    if peer.route != voter.binding.run_route {
                        return Err(Fault::Unavailable);
                    }
                    let endpoint = peer.endpoint_pin();
                    stored_managed(store, lease, move |store| {
                        store.managed_require_run_pin(&endpoint)
                    })
                    .await?;
                    let pin = peer
                        .current_pin("attempt_current_egress_v1")
                        .await
                        .map_err(|_| Fault::Unavailable)?;
                    let request_id = crate::domain::id();
                    let transport_id = crate::domain::id();
                    let staged_id = request_id.clone();
                    let bound = voter.attempt.clone();
                    let owner = owner.clone();
                    let query = stored_managed(store, lease, move |store| {
                        store.managed_stage_egress(&pin, &bound, &staged_id, &transport_id, &owner)
                    })
                    .await?;
                    let current = peer
                        .current_egress(&query)
                        .await
                        .map_err(|_| Fault::Unavailable)?;
                    if current.receipt().attempt == voter.attempt {
                        return Err(Fault::Unavailable);
                    }
                    let mut successor = voter.binding.clone();
                    successor.attempt = current.receipt().attempt.clone();
                    successor.actor = current.receipt().actor.clone();
                    let incarnation = current.receipt().incarnation.clone();
                    let old = voter.binding.clone();
                    stored_managed(store, lease, move |store| {
                        store.managed_record_current(&request_id, &current)?;
                        store.managed_rebind(&current, &old, &successor, &incarnation, "egress")
                    })
                    .await?;
                    rebound = true;
                }
                if rebound {
                    let refreshed = stored_managed(store, lease, move |store| {
                        store.managed_refresh_consensus(pending)
                    })
                    .await?;
                    return refreshed.verify(&authority);
                }
                pending.verify(&authority)
            })
        }
    }

    pub(super) struct Read {
        pub bootstrap_id: String,
        pub context_id: String,
        pub command: Command,
        pub digest: String,
        pub authorities: Vec<CurrentAuthority>,
        pub consumed: Consumed,
    }

    /// Immediate reads use the same live bootstrap lease and binding CAS.
    pub(super) async fn read(
        store: &SharedStore,
        activity: &Arc<ManagedActivity>,
        bootstrap: &ManagedLease,
        request: Read,
    ) -> Result<Reply, Fault> {
        if !Arc::ptr_eq(&bootstrap._inner.activity, activity)
            || bootstrap._inner.work != ManagedWork::Bootstrap(request.bootstrap_id.clone())
        {
            return Err(Fault::Unauthorized);
        }
        stored_managed(store, bootstrap, move |store| {
            store.managed_read(
                &request.bootstrap_id,
                &request.context_id,
                &request.command,
                &request.digest,
                &request.authorities,
                &request.consumed,
            )
        })
        .await
    }

    pub(super) struct Mutation {
        pub bootstrap_id: String,
        pub context_id: String,
        pub intent_id: String,
        pub member_id: String,
        pub command: Command,
        pub digest: String,
        pub authority: CurrentAuthority,
        pub consumed: Consumed,
        pub pool_route: Route,
    }

    /// The bootstrap lease is acquired before Bridge I/O and transferred only
    /// after the intent lease is held. No store mutex crosses Run I/O.
    pub(super) async fn mutation<C: Client>(
        store: &SharedStore,
        activity: &Arc<ManagedActivity>,
        bootstrap: &ManagedLease,
        request: Mutation,
        client: &C,
    ) -> Result<IntentReservation, Fault> {
        if !Arc::ptr_eq(&bootstrap._inner.activity, activity)
            || bootstrap._inner.work != ManagedWork::Bootstrap(request.bootstrap_id.clone())
        {
            return Err(Fault::Unauthorized);
        }
        let Some(lease) = activity.acquire(ManagedWork::Intent(request.intent_id.clone()))? else {
            return Err(Fault::Unavailable);
        };
        let intent_id = request.intent_id.clone();
        let digest = request.digest.clone();
        let is_vote = matches!(request.command, Command::Vote(_));
        let (reservation, plan) = stored_managed(store, &lease, move |store| {
            store.managed_reserve(
                &request.bootstrap_id,
                &request.context_id,
                &request.intent_id,
                &request.member_id,
                &request.command,
                &request.digest,
                request.authority,
                &request.consumed,
                &request.pool_route,
            )
        })
        .await?;
        if reservation != IntentReservation::Created {
            return Ok(reservation);
        }
        let plan = plan.ok_or(Fault::Internal)?;
        let result = async {
            // A definitive early-hook refusal may retry the exact same intent
            // while Run rechecks the original Bridge observation. This local
            // deadline bounds waiting; it never infers Bridge freshness.
            let admission = tokio::time::timeout(EXCHANGE_TIMEOUT, async {
                loop {
                    match client.admit(&plan).await {
                        Ok(admission) => break Ok(admission),
                        Err(RunError::NotReady) => {
                            tokio::time::sleep(Duration::from_millis(250)).await;
                        }
                        Err(_) => break Err(Fault::Unavailable),
                    }
                }
            })
            .await
            .map_err(|_| Fault::Unavailable)??;
            let id = intent_id.clone();
            let hash = digest.clone();
            stored_managed(store, &lease, move |store| {
                store.managed_mark_admitted(&id, &hash, &admission)
            })
            .await?;
            if is_vote {
                let id = intent_id.clone();
                let hash = digest.clone();
                let pending = stored_managed(store, &lease, move |store| {
                    store.managed_snapshot_consensus(&id, &hash)
                })
                .await?;
                let fence = client.consensus(pending, store, &lease).await?;
                let id = intent_id.clone();
                let hash = digest.clone();
                stored_managed(store, &lease, move |store| {
                    store.managed_commit_vote(&id, &hash, fence)
                })
                .await
            } else {
                let id = intent_id.clone();
                let hash = digest.clone();
                stored_managed(store, &lease, move |store| {
                    store.managed_commit_domain(&id, &hash)
                })
                .await
            }
        }
        .await;
        match result {
            Ok(receipt) => Ok(IntentReservation::Committed(receipt)),
            Err(error) => {
                // If commit already won, this conflicts without undoing it; the
                // recovery worker settles the retained terminal outcome.
                let _ = stored_managed(store, &lease, move |store| {
                    store.managed_terminal_abort(&intent_id, &digest)
                })
                .await;
                Err(error)
            }
        }
    }
}

/// P3 owner enrollment reconciliation. Every key and payload is durable before
/// Run I/O; recovery uses only the original key, never a new start.
pub(crate) mod enrollment_dispatch {
    use super::*;
    use crate::managed_enrollment::{
        self as journal, Attested, EnrollmentRoute, Failure, Key, Lookup, OldStatus, StartReceipt,
        Switch,
    };
    use crate::managed_run::RunPeer;
    use crate::run_status::Target;
    use serde_json::Value;
    use std::{future::Future, pin::Pin};

    pub(crate) type Response<'a, T> = Pin<Box<dyn Future<Output = Result<T, Failure>> + Send + 'a>>;

    /// Authenticated Run enrollment operations and the old-lineage status read.
    pub(crate) trait Client: Send + Sync {
        /// Currently configured route identity, compared with every frozen key.
        fn route(&self) -> EnrollmentRoute;
        /// Whether NEW admissions are switched on.
        fn switch_enabled(&self) -> bool;
        fn enabled(&self) -> Response<'_, ()>;
        fn submit<'a>(&'a self, params: &'a Value) -> Response<'a, StartReceipt>;
        fn lookup<'a>(&'a self, key: &'a Key) -> Response<'a, Lookup>;
        fn abort<'a>(&'a self, key: &'a Key) -> Response<'a, Lookup>;
        fn current<'a>(
            &'a self,
            key: &'a Key,
            member: &'a str,
            request: &'a str,
        ) -> Response<'a, Attested>;
        fn status<'a>(
            &'a self,
            store: &'a str,
            target: &'a Target,
        ) -> Pin<Box<dyn Future<Output = OldStatus> + Send + 'a>>;
    }

    /// The configured route for NEW enrollments; absent when not fully provisioned.
    pub(crate) fn configured_route(config: &Config, pool_store: &str) -> Option<EnrollmentRoute> {
        let transport = config.managed_run_transport.as_ref()?;
        let peer = RunPeer::from_config(config, pool_store).ok()?;
        Some(EnrollmentRoute {
            run: peer.endpoint_pin(),
            pool_route: peer.pool_route.clone(),
            bridge_route: peer.bridge_route.clone(),
            producer: peer.producer.clone(),
            role: transport.managed_role.clone().unwrap_or_default(),
            status: configured_run_route(config).ok(),
        })
    }

    /// Production client over the pinned Run attempt endpoint and public status socket.
    pub(crate) struct Live {
        config: Config,
        peer: RunPeer,
        route: EnrollmentRoute,
    }
    impl Live {
        pub(crate) fn new(config: &Config, pool_store: &str) -> Option<Self> {
            Some(Self {
                config: config.clone(),
                peer: RunPeer::from_config(config, pool_store).ok()?,
                route: configured_route(config, pool_store)?,
            })
        }
    }
    impl Client for Live {
        fn route(&self) -> EnrollmentRoute {
            self.route.clone()
        }
        fn switch_enabled(&self) -> bool {
            self.config
                .managed_run_transport
                .as_ref()
                .is_some_and(|transport| transport.enrollment_enabled)
        }
        fn enabled(&self) -> Response<'_, ()> {
            Box::pin(async move { self.peer.enrollment_enabled().await })
        }
        fn submit<'a>(&'a self, params: &'a Value) -> Response<'a, StartReceipt> {
            Box::pin(async move { self.peer.enrollment_submit(params).await })
        }
        fn lookup<'a>(&'a self, key: &'a Key) -> Response<'a, Lookup> {
            Box::pin(async move { self.peer.enrollment_lookup(key).await })
        }
        fn abort<'a>(&'a self, key: &'a Key) -> Response<'a, Lookup> {
            Box::pin(async move { self.peer.enrollment_abort(key).await })
        }
        fn current<'a>(
            &'a self,
            key: &'a Key,
            member: &'a str,
            request: &'a str,
        ) -> Response<'a, Attested> {
            Box::pin(async move { self.peer.enrollment_current(key, member, request).await })
        }
        fn status<'a>(
            &'a self,
            store: &'a str,
            target: &'a Target,
        ) -> Pin<Box<dyn Future<Output = OldStatus> + Send + 'a>> {
            Box::pin(async move {
                let pinned = self.route.status.as_ref();
                if !configured_run_route(&self.config).is_ok_and(|configured| {
                    pinned.is_some_and(|route| {
                        configured.socket == route.socket
                            && configured.expected_uid == route.expected_uid
                            && configured.peer_uid == route.peer_uid
                    })
                }) {
                    return OldStatus::Unavailable;
                }
                let Ok(snapshot) =
                    integrations::run_status(&self.config, store, std::slice::from_ref(target))
                        .await
                else {
                    return OldStatus::Unavailable;
                };
                let Some(item) = snapshot.items().next() else {
                    return OldStatus::Unavailable;
                };
                match item.replacement_precondition() {
                    Some(target) => OldStatus::Ready(target),
                    None if item.replacement_not_ready() => OldStatus::NotReady,
                    None => OldStatus::Unavailable,
                }
            })
        }
    }

    /// Fixed bounded diagnostic of one Run job snapshot.
    fn job_reason(state: &journal::JobState) -> &'static str {
        match (state.state.as_str(), state.failure_code.as_deref()) {
            (_, Some("preparation_rejected")) => "preparation_rejected",
            (_, Some("supervisor_spawn_failed")) => "supervisor_spawn_failed",
            (_, Some(_)) => "execution_failed",
            ("not_started", None) => "not_started",
            ("starting", None) => "starting",
            ("qualification_pending", None) => "qualification_pending",
            ("qualified", None) => "attempt_not_ready",
            ("terminal", None) => "terminal",
            _ => "unknown",
        }
    }

    fn lookup_matches(enrollment: &journal::Enrollment, lookup: &Lookup) -> bool {
        lookup.version == 1
            && lookup.store_id == enrollment.route.run.route.component_store_id
            && lookup.request_id == enrollment.request_id
            && Some(&lookup.fingerprint) == enrollment.fingerprint.as_ref()
            && match lookup.state.as_str() {
                "admitted" => lookup.receipt.is_some(),
                "absent" | "aborted" => lookup.receipt.is_none() && lookup.jobs_state.is_empty(),
                _ => false,
            }
    }

    async fn note(store: &SharedStore, id: &str, code: &'static str) -> Result<(), Fault> {
        let id = id.to_owned();
        stored(store, move |store| {
            journal::note(store.completion_db(), &id, code)
        })
        .await
    }

    async fn note_job(
        store: &SharedStore,
        id: &str,
        index: usize,
        code: &'static str,
    ) -> Result<(), Fault> {
        let id = id.to_owned();
        stored(store, move |store| {
            journal::note_job(store.completion_db(), &id, index, code)
        })
        .await
    }

    async fn apply_lookup(
        store: &SharedStore,
        enrollment: &journal::Enrollment,
        lookup: Lookup,
    ) -> Result<bool, Fault> {
        if !lookup_matches(enrollment, &lookup) {
            note(store, &enrollment.id, "outcome_unknown").await?;
            return Ok(false);
        }
        let id = enrollment.id.clone();
        match (lookup.state.as_str(), lookup.receipt) {
            ("admitted", Some(receipt)) => {
                let recorded = stored(store, move |store| {
                    journal::record_admission(store.completion_db(), &id, &receipt)
                })
                .await;
                if recorded.is_err() {
                    note(store, &enrollment.id, "receipt_mismatch").await?;
                }
                Ok(false)
            }
            ("aborted", None) => {
                stored(store, move |store| {
                    journal::record_aborted(store.completion_db(), &id)
                })
                .await?;
                Ok(false)
            }
            _ => Ok(true),
        }
    }

    async fn submit<C: Client>(
        store: &SharedStore,
        client: &C,
        enrollment: &journal::Enrollment,
        first: bool,
    ) -> Result<(), Fault> {
        let params = enrollment.params.as_ref().ok_or(Fault::Internal)?;
        let id = enrollment.id.clone();
        match client.submit(params).await {
            Ok(receipt) => {
                let recorded = stored(store, move |store| {
                    journal::record_admission(store.completion_db(), &id, &receipt)
                })
                .await;
                if recorded.is_err() {
                    note(store, &enrollment.id, "receipt_mismatch").await?;
                }
            }
            Err(Failure::Refused(code)) => {
                if first {
                    // Fence Run's key (idempotent) before settling, so a key it
                    // left prepared becomes a tombstone instead of leaking.
                    match client.abort(&enrollment.key()?).await {
                        Ok(lookup) if lookup.state == "aborted" => {}
                        Ok(lookup) => {
                            apply_lookup(store, enrollment, lookup).await?;
                            return Ok(());
                        }
                        Err(failure) => {
                            // Retry the exact-key abort on later passes.
                            let id = id.clone();
                            stored(store, move |store| {
                                journal::request_abort(store.completion_db(), &id)
                            })
                            .await?;
                            return note(store, &enrollment.id, failure.code()).await;
                        }
                    }
                }
                stored(store, move |store| {
                    journal::record_refusal(store.completion_db(), &id, code, first)
                })
                .await?;
            }
            Err(Failure::Aborted) => {
                stored(store, move |store| {
                    journal::record_aborted(store.completion_db(), &id)
                })
                .await?;
            }
            Err(failure) => note(store, &enrollment.id, failure.code()).await?,
        }
        Ok(())
    }

    /// Advance one enrollment at most one Run step per call, observing every
    /// admitted job (no pacing). The resident uses the paced `reconcile`.
    #[cfg(test)]
    pub(crate) async fn drive<C: Client>(
        store: &SharedStore,
        client: &C,
        id: &str,
    ) -> Result<(), Fault> {
        advance(store, client, id, &mut Unpaced).await.map(|_| ())
    }

    /// Per-job admission of one reconciliation pass.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum Turn {
        /// Observe this job now.
        Go,
        /// Backed off: skip it this pass.
        Skip,
        /// Pass budget exhausted: stop before this job.
        Stop,
    }

    /// Pacing of the admitted jobs of one enrollment.
    pub(crate) trait Pace: Send {
        fn turn(&mut self, id: &str, index: usize) -> Turn;
        /// `waiting`: no progress (not ready, refusal or uncertainty), back off.
        fn observed(&mut self, id: &str, index: usize, waiting: bool);
    }

    struct Unpaced;
    impl Pace for Unpaced {
        fn turn(&mut self, _: &str, _: usize) -> Turn {
            Turn::Go
        }
        fn observed(&mut self, _: &str, _: usize, _: bool) {}
    }

    /// One Run step for `id`; returns `false` only when the pace stopped it
    /// before every due admitted job had its turn.
    async fn advance<C: Client>(
        store: &SharedStore,
        client: &C,
        id: &str,
        pace: &mut dyn Pace,
    ) -> Result<bool, Fault> {
        let load_id = id.to_owned();
        let (enrollment, jobs) = stored(store, move |store| {
            journal::load(store.completion_db(), &load_id)
        })
        .await?;
        if !client.route().same_identity(&enrollment.route) {
            return note(store, id, "route_changed").await.map(|()| true);
        }
        if enrollment.state == "admitted" {
            let key = enrollment.key()?;
            for job in jobs.iter().filter(|job| job.state == "admitted") {
                match pace.turn(id, job.index) {
                    Turn::Go => {}
                    Turn::Skip => continue,
                    Turn::Stop => return Ok(false),
                }
                let waiting = observe(store, client, &enrollment, &key, job).await?;
                pace.observed(id, job.index, waiting);
            }
            return Ok(true);
        }
        submit_step(store, client, id, enrollment)
            .await
            .map(|()| true)
    }

    /// The next Run step of one unsubmitted or uncertain enrollment.
    async fn submit_step<C: Client>(
        store: &SharedStore,
        client: &C,
        id: &str,
        mut enrollment: journal::Enrollment,
    ) -> Result<(), Fault> {
        match enrollment.state.as_str() {
            "reserved" => {
                if !client.switch_enabled() {
                    let id = id.to_owned();
                    return stored(store, move |store| {
                        journal::refuse_unsubmitted(
                            store.completion_db(),
                            &id,
                            "capability_missing",
                        )
                    })
                    .await;
                }
                if let (Some(replacement), None) =
                    (enrollment.replacement.clone(), enrollment.params.as_ref())
                {
                    let id = id.to_owned();
                    match client
                        .status(&replacement.store_id, &replacement.target)
                        .await
                    {
                        OldStatus::Ready(precondition) => {
                            stored(store, move |store| {
                                journal::freeze_precondition(
                                    store.completion_db(),
                                    &id,
                                    &precondition,
                                )
                            })
                            .await?;
                        }
                        OldStatus::NotReady => {
                            return stored(store, move |store| {
                                journal::refuse_unsubmitted(
                                    store.completion_db(),
                                    &id,
                                    "precondition_failed",
                                )
                            })
                            .await;
                        }
                        OldStatus::Unavailable => return note(store, &id, "run_unavailable").await,
                    }
                    let load_id = enrollment.id.clone();
                    enrollment = stored(store, move |store| {
                        journal::load(store.completion_db(), &load_id)
                    })
                    .await?
                    .0;
                }
                match client.enabled().await {
                    Ok(()) => {}
                    Err(Failure::Refused(_)) => {
                        let id = id.to_owned();
                        return stored(store, move |store| {
                            journal::refuse_unsubmitted(
                                store.completion_db(),
                                &id,
                                "capability_missing",
                            )
                        })
                        .await;
                    }
                    Err(_) => return note(store, id, "run_unavailable").await,
                }
                let begin = id.to_owned();
                stored(store, move |store| {
                    journal::begin_submit(store.completion_db(), &begin)
                })
                .await?;
                submit(store, client, &enrollment, true).await
            }
            "submit_possible" => {
                let begin = id.to_owned();
                stored(store, move |store| {
                    journal::begin_recovery(store.completion_db(), &begin)
                })
                .await?;
                let key = enrollment.key()?;
                if enrollment.abort_requested {
                    return match client.abort(&key).await {
                        Ok(lookup) if lookup.state != "absent" => {
                            apply_lookup(store, &enrollment, lookup).await.map(|_| ())
                        }
                        Ok(_) => note(store, id, "outcome_unknown").await,
                        Err(failure) => note(store, id, failure.code()).await,
                    };
                }
                match client.lookup(&key).await {
                    Ok(lookup) => {
                        if apply_lookup(store, &enrollment, lookup).await? {
                            // Absent is only a snapshot: replay the SAME key and payload.
                            submit(store, client, &enrollment, false).await?;
                        }
                        Ok(())
                    }
                    // A prepared Run key continues only through same-key replay.
                    Err(Failure::InProgress) => submit(store, client, &enrollment, false).await,
                    Err(failure) => note(store, id, failure.code()).await,
                }
            }
            _ => Ok(()),
        }
    }

    /// Observe one admitted job; returns whether it is still waiting (not
    /// ready, refused or uncertain), so the scheduler backs it off.
    async fn observe<C: Client>(
        store: &SharedStore,
        client: &C,
        enrollment: &journal::Enrollment,
        key: &Key,
        job: &journal::Job,
    ) -> Result<bool, Fault> {
        let id = enrollment.id.clone();
        let index = job.index;
        let Some((request, fresh)) = stored(store, move |store| {
            journal::stage_observation(store.completion_db(), &id, index)
        })
        .await?
        else {
            return Ok(false);
        };
        let settle = |retain: bool| {
            let id = enrollment.id.clone();
            let request = request.clone();
            async move {
                stored(store, move |store| {
                    journal::settle_observation(store.completion_db(), &id, index, &request, retain)
                })
                .await
            }
        };
        match client.current(key, &job.member, &request).await {
            // A replay of an uncertain earlier observation is never fresh authority.
            Ok(_) if !fresh => settle(false).await.map(|()| false),
            Ok(attested) => {
                let attested = Arc::new(attested);
                if enrollment.mode == "start" {
                    let id = enrollment.id.clone();
                    let bound = Arc::clone(&attested);
                    let result = stored(store, move |store| {
                        journal::bind_attested(store.completion_db(), &id, index, &bound)
                    })
                    .await;
                    settle(false).await?;
                    match result {
                        Ok(_) => Ok(false),
                        Err(Fault::Conflict) => {
                            note_job(store, &enrollment.id, index, "address_conflict").await?;
                            Ok(true)
                        }
                        Err(_) => {
                            note_job(store, &enrollment.id, index, "attestation_mismatch").await?;
                            Ok(true)
                        }
                    }
                } else {
                    let replacement = enrollment.replacement.as_ref().ok_or(Fault::Internal)?;
                    let precondition: Target = serde_json::from_value(
                        enrollment
                            .params
                            .as_ref()
                            .and_then(|params| params["preconditions"].get(0))
                            .cloned()
                            .ok_or(Fault::Internal)?,
                    )
                    .map_err(|_| Fault::Internal)?;
                    let status = client.status(&replacement.store_id, &precondition).await;
                    let outcome = match status {
                        OldStatus::Ready(latest) if latest == precondition => {
                            let id = enrollment.id.clone();
                            let switched = Arc::clone(&attested);
                            stored(store, move |store| {
                                journal::switch(store.completion_db(), &id, &switched)
                            })
                            .await
                        }
                        OldStatus::Ready(_) | OldStatus::NotReady => {
                            Ok(Switch::Attention("old_resumed"))
                        }
                        OldStatus::Unavailable => Ok(Switch::Attention("run_unavailable")),
                    };
                    settle(false).await?;
                    match outcome {
                        Ok(Switch::Attention(code)) => {
                            note(store, &enrollment.id, code).await?;
                            Ok(true)
                        }
                        Ok(_) => Ok(false),
                        Err(Fault::Conflict) => {
                            note_job(store, &enrollment.id, index, "address_conflict").await?;
                            Ok(true)
                        }
                        Err(_) => {
                            note_job(store, &enrollment.id, index, "attestation_mismatch").await?;
                            Ok(true)
                        }
                    }
                }
            }
            Err(Failure::NotReady) => {
                settle(true).await?;
                let reason = match client.lookup(key).await {
                    Ok(lookup) if lookup_matches(enrollment, &lookup) => lookup
                        .jobs_state
                        .iter()
                        .find(|state| state.index == index && state.member_id == job.member)
                        .map_or("attempt_not_ready", job_reason),
                    _ => "attempt_not_ready",
                };
                note_job(store, &enrollment.id, index, reason).await?;
                Ok(true)
            }
            // A typed refusal created no receipt; the next observation uses a fresh key.
            Err(
                failure @ (Failure::Stale
                | Failure::Refused(_)
                | Failure::Aborted
                | Failure::Operator(_)),
            ) => {
                settle(false).await?;
                note_job(store, &enrollment.id, index, failure.code()).await?;
                Ok(true)
            }
            // Uncertain transport: the same key is recovered next, never trusted as fresh.
            Err(failure) => {
                note_job(store, &enrollment.id, index, failure.code()).await?;
                Ok(true)
            }
        }
    }

    /// Pending enrollments read per keyset page.
    pub(crate) const PAGE: u32 = 64;
    /// Run calls one reconciliation pass may make; the rest of the tick
    /// (egress, scope retirement, completion) always runs after it.
    pub(crate) const PASS_BUDGET: usize = 64;
    /// Worst-case Run calls of one enrollment step (status, enabled, submit).
    const STEP_CALLS: usize = 3;
    /// Worst-case Run calls of one job observation (current, lookup or status).
    const JOB_CALLS: usize = 2;
    /// Exponential backoff of a waiting enrollment or job, in seconds.
    const BACKOFF_BASE: u64 = 5;
    const BACKOFF_CAP: u64 = 300;

    /// A scheduled unit: an unsubmitted/uncertain enrollment or one admitted job.
    type Slot = (String, Option<usize>);

    #[derive(Clone, Copy, Debug)]
    struct Backoff {
        failures: u32,
        due: u64,
        revision: Option<u64>,
    }

    /// Resident in-memory reconciliation schedule: a rotating keyset cursor and
    /// per-enrollment/per-job exponential backoff (capped at 300 s). Losing it
    /// on restart only makes every unit due again; it is never authority.
    #[derive(Debug, Default)]
    pub(crate) struct Schedule {
        /// Next keyset position (inclusive); 0 restarts the rotation.
        next: i64,
        slots: std::collections::HashMap<Slot, Backoff>,
        /// Enrollments seen since the rotation last restarted, for pruning.
        seen: std::collections::HashSet<String>,
    }
    impl Schedule {
        /// A unit is due once its backoff elapsed; an enrollment is also due
        /// when its revision moved (for example an owner abort request).
        fn due(&self, slot: &Slot, revision: Option<u64>, now: u64) -> bool {
            self.slots.get(slot).is_none_or(|backoff| {
                now >= backoff.due || (revision.is_some() && backoff.revision != revision)
            })
        }
        fn wait(&mut self, slot: Slot, revision: Option<u64>, now: u64) {
            let backoff = self.slots.entry(slot).or_insert(Backoff {
                failures: 0,
                due: now,
                revision,
            });
            backoff.failures = backoff.failures.saturating_add(1);
            let delay = (BACKOFF_BASE << (backoff.failures - 1).min(6)).min(BACKOFF_CAP);
            backoff.due = now.saturating_add(delay);
            backoff.revision = revision;
        }
        fn clear(&mut self, slot: &Slot) {
            self.slots.remove(slot);
        }
        /// Backoff deadline of a unit, for diagnostics and tests.
        #[cfg(test)]
        pub(crate) fn due_at(&self, id: &str, index: Option<usize>) -> Option<u64> {
            self.slots
                .get(&(id.to_owned(), index))
                .map(|backoff| backoff.due)
        }
    }

    /// Counts every Run call of one pass.
    struct Metered<'a, C> {
        inner: &'a C,
        calls: std::sync::atomic::AtomicUsize,
    }
    impl<C> Metered<'_, C> {
        fn tick(&self) {
            self.calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        fn calls(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::Relaxed)
        }
        fn fits(&self, cost: usize) -> bool {
            self.calls().saturating_add(cost) <= PASS_BUDGET
        }
    }
    impl<C: Client> Client for Metered<'_, C> {
        fn route(&self) -> EnrollmentRoute {
            self.inner.route()
        }
        fn switch_enabled(&self) -> bool {
            self.inner.switch_enabled()
        }
        fn enabled(&self) -> Response<'_, ()> {
            self.tick();
            self.inner.enabled()
        }
        fn submit<'a>(&'a self, params: &'a Value) -> Response<'a, StartReceipt> {
            self.tick();
            self.inner.submit(params)
        }
        fn lookup<'a>(&'a self, key: &'a Key) -> Response<'a, Lookup> {
            self.tick();
            self.inner.lookup(key)
        }
        fn abort<'a>(&'a self, key: &'a Key) -> Response<'a, Lookup> {
            self.tick();
            self.inner.abort(key)
        }
        fn current<'a>(
            &'a self,
            key: &'a Key,
            member: &'a str,
            request: &'a str,
        ) -> Response<'a, Attested> {
            self.tick();
            self.inner.current(key, member, request)
        }
        fn status<'a>(
            &'a self,
            store: &'a str,
            target: &'a Target,
        ) -> Pin<Box<dyn Future<Output = OldStatus> + Send + 'a>> {
            self.tick();
            self.inner.status(store, target)
        }
    }

    /// Per-job pacing of one pass: backoff and the shared I/O budget.
    struct Paced<'a, C> {
        schedule: &'a mut Schedule,
        meter: &'a Metered<'a, C>,
        now: u64,
    }
    impl<C: Client> Pace for Paced<'_, C> {
        fn turn(&mut self, id: &str, index: usize) -> Turn {
            if !self
                .schedule
                .due(&(id.to_owned(), Some(index)), None, self.now)
            {
                Turn::Skip
            } else if self.meter.fits(JOB_CALLS) {
                Turn::Go
            } else {
                Turn::Stop
            }
        }
        fn observed(&mut self, id: &str, index: usize, waiting: bool) {
            let slot = (id.to_owned(), Some(index));
            if waiting {
                self.schedule.wait(slot, None, self.now);
            } else {
                self.schedule.clear(&slot);
            }
        }
    }

    /// One bounded, fair pass over pending enrollments; returns the Run calls
    /// made (never above `PASS_BUDGET`). The keyset cursor rotates through the
    /// whole journal, units that keep waiting back off exponentially, and a
    /// pass that exhausts its budget resumes at the same enrollment next time.
    /// One enrollment's failure never stops the others.
    pub(crate) async fn reconcile<C: Client>(
        store: &SharedStore,
        client: &C,
        stopped: &watch::Receiver<bool>,
        schedule: &mut Schedule,
        now: u64,
    ) -> Result<usize, Fault> {
        let meter = Metered {
            inner: client,
            calls: std::sync::atomic::AtomicUsize::new(0),
        };
        let from = schedule.next;
        let page = stored(store, move |store| {
            journal::pending(store.completion_db(), from, PAGE)
        })
        .await?;
        let last_page = page.len() < usize::try_from(PAGE).map_err(|_| Fault::Internal)?;
        for pending in page {
            if *stopped.borrow() {
                return Ok(meter.calls());
            }
            schedule.seen.insert(pending.id.clone());
            let enrollment_slot = (pending.id.clone(), None);
            let complete = if pending.state == "admitted" {
                let mut pace = Paced {
                    schedule: &mut *schedule,
                    meter: &meter,
                    now,
                };
                advance(store, &meter, &pending.id, &mut pace).await
            } else if !schedule.due(&enrollment_slot, Some(pending.revision), now) {
                Ok(true)
            } else if !meter.fits(STEP_CALLS) {
                Ok(false)
            } else {
                let result = advance(store, &meter, &pending.id, &mut Unpaced).await;
                let load_id = pending.id.clone();
                let after = stored(store, move |store| {
                    journal::load(store.completion_db(), &load_id)
                })
                .await
                .map(|(enrollment, _)| (enrollment.state, enrollment.revision));
                match after {
                    Ok((state, _)) if result.is_ok() && state != pending.state => {
                        schedule.clear(&enrollment_slot);
                    }
                    Ok((_, revision)) => schedule.wait(enrollment_slot, Some(revision), now),
                    Err(_) => schedule.wait(enrollment_slot, None, now),
                }
                result
            };
            match complete {
                Ok(true) => schedule.next = pending.rowid.saturating_add(1),
                // Budget exhausted: the next pass resumes at this enrollment.
                Ok(false) => {
                    schedule.next = pending.rowid;
                    return Ok(meter.calls());
                }
                Err(_) => {
                    eprintln!("managed enrollment reconciliation deferred");
                    schedule.next = pending.rowid.saturating_add(1);
                }
            }
        }
        if last_page {
            // The rotation saw every pending enrollment: restart it and forget
            // backoff of enrollments that are no longer pending.
            let seen = std::mem::take(&mut schedule.seen);
            schedule.slots.retain(|(id, _), _| seen.contains(id));
            schedule.next = 0;
        }
        Ok(meter.calls())
    }
}

/// Egress performs Run reads and Bridge calls outside the Store mutex.
mod managed_egress_dispatch {
    use super::*;
    use crate::managed_egress::{Frozen, OwnerClient, OwnerFailure, State, Target};
    use crate::managed_run::{ActorRecovery, CurrentAuthority, EgressQuery, RunError, RunPeer};
    use crate::managed_state::{RunEndpointPin, RunPin};
    use std::{future::Future, pin::Pin};

    type Response<'a, T> = Pin<Box<dyn Future<Output = Result<T, RunError>> + Send + 'a>>;
    pub(super) trait CurrentClient {
        fn endpoint(&self) -> RunEndpointPin;
        fn pool_route(&self) -> crate::managed_state::Route;
        fn current_pin(&self) -> Response<'_, RunPin>;
        fn current<'a>(&'a self, query: &'a EgressQuery) -> Response<'a, CurrentAuthority>;
    }
    impl CurrentClient for RunPeer {
        fn endpoint(&self) -> RunEndpointPin {
            self.endpoint_pin()
        }
        fn pool_route(&self) -> crate::managed_state::Route {
            self.pool_route.clone()
        }
        fn current_pin(&self) -> Response<'_, RunPin> {
            Box::pin(async move { RunPeer::current_pin(self, "attempt_current_egress_v1").await })
        }
        fn current<'a>(&'a self, query: &'a EgressQuery) -> Response<'a, CurrentAuthority> {
            Box::pin(async move { self.current_egress(query).await })
        }
    }

    async fn note(
        store: &SharedStore,
        lease: &ManagedLease,
        id: &str,
        reason: &'static str,
    ) -> Result<(), Fault> {
        let id = id.to_owned();
        stored_managed(store, lease, move |store| {
            store.egress_attention(&id, reason)
        })
        .await
    }
    fn require_effect_lease(lease: &ManagedLease, id: &str) -> Result<(), Fault> {
        if lease._inner.work != ManagedWork::Egress(id.into()) {
            return Err(Fault::Unauthorized);
        }
        Ok(())
    }
    fn actor_reason(error: RunError) -> &'static str {
        match error {
            RunError::ActorRecovery(ActorRecovery::AwaitingRootHook) => "awaiting_root_hook",
            RunError::ActorRecovery(ActorRecovery::RelaunchRequired) => "actor_relaunch_required",
            RunError::ActorRecovery(ActorRecovery::Unavailable) => "actor_unavailable",
            RunError::NotReady => "attempt_not_ready",
            _ => "binding_unavailable",
        }
    }
    fn bridge_reason(error: OwnerFailure) -> &'static str {
        match error {
            OwnerFailure::RelaunchRequired => "relaunch_required",
            OwnerFailure::NotSent(reason) => reason,
            OwnerFailure::Unknown => "outcome_unknown",
        }
    }

    /// Retry a pinned currentness key until Run fences it as stale after relaunch.
    #[allow(
        clippy::too_many_arguments,
        reason = "The pre-I/O pins and original event seed remain distinct"
    )]
    pub(super) async fn freeze_target<R: CurrentClient>(
        store: &SharedStore,
        lease: &ManagedLease,
        target: Target,
        prefix: String,
        run: &R,
        bridge_pin: crate::managed_bridge::BridgePin,
        audience: String,
    ) -> Result<Option<Frozen>, Fault> {
        let id = target.seed.effect_id.clone();
        require_effect_lease(lease, &id)?;
        let bridge = bridge_pin.clone();
        let endpoint = run.endpoint();
        let pool_route = run.pool_route();
        match stored_managed(store, lease, move |store| {
            store.managed_pin_routes(&bridge, &endpoint, &pool_route)
        })
        .await
        {
            Ok(()) => {}
            // A stale pin refuses this managed delivery only; the resident keeps serving.
            Err(Fault::Conflict) => {
                stale_route_pin();
                note(store, lease, &id, "route_unavailable").await?;
                return Ok(None);
            }
            Err(error) => return Err(error),
        }
        let run_pin = match run.current_pin().await {
            Ok(pin) => pin,
            Err(error) => {
                note(store, lease, &id, actor_reason(error)).await?;
                return Ok(None);
            }
        };
        let probing = target.clone();
        let discovered = run_pin.clone();
        let (request_id, run_pin, was_uncertain) =
            match stored_managed(store, lease, move |store| {
                store.egress_probe(&probing, &discovered)
            })
            .await
            {
                Ok(probe) => probe,
                Err(_) => {
                    note(store, lease, &id, "binding_unavailable").await?;
                    return Ok(None);
                }
            };
        let stage_id = request_id.clone();
        let stage_effect = id.clone();
        let bound = target.binding.attempt.clone();
        let pinned = run_pin.clone();
        let query = match stored_managed(store, lease, move |store| {
            store.egress_stage(
                &stage_effect,
                &pinned,
                &bound,
                &stage_id,
                &crate::domain::id(),
            )
        })
        .await
        {
            Ok(query) => query,
            Err(_) => {
                note(store, lease, &id, "capability_missing").await?;
                return Ok(None);
            }
        };
        let marked_effect = id.clone();
        let marked_request = request_id.clone();
        match stored_managed(store, lease, move |store| {
            store.egress_probe_inflight(&marked_effect, &marked_request, true)
        })
        .await
        {
            Ok(()) => {}
            Err(Fault::Stale) => return Ok(None),
            Err(error) => return Err(error),
        }
        let authority = match run.current(&query).await {
            Ok(_) if was_uncertain => {
                // This may be a replay of a receipt issued before the lost
                // response or restart; only a new Run observation is fresh.
                let key = id.clone();
                let old = request_id.clone();
                match stored_managed(store, lease, move |store| {
                    store.egress_reset_probe(&key, &old)
                })
                .await
                {
                    Ok(()) | Err(Fault::Stale) => {}
                    Err(fault) => return Err(fault),
                }
                note(store, lease, &id, "binding_unavailable").await?;
                return Ok(None);
            }
            Ok(authority) => authority,
            Err(error) => {
                if error == RunError::DifferentLineage {
                    let key = id.clone();
                    stored_managed(store, lease, move |store| {
                        store.egress_not_delivered(&key, "different_lineage")
                    })
                    .await?;
                    return Ok(None);
                }
                if error == RunError::BindingStale {
                    let key = id.clone();
                    let old = request_id.clone();
                    match stored_managed(store, lease, move |store| {
                        store.egress_reset_probe(&key, &old)
                    })
                    .await
                    {
                        Ok(()) | Err(Fault::Stale) => {}
                        Err(fault) => return Err(fault),
                    }
                } else if matches!(error, RunError::NotReady | RunError::ActorRecovery(_)) {
                    // A correlated refusal proves this key has no receipt yet.
                    let key = id.clone();
                    let same = request_id.clone();
                    match stored_managed(store, lease, move |store| {
                        store.egress_probe_inflight(&key, &same, false)
                    })
                    .await
                    {
                        Ok(()) | Err(Fault::Stale) => {}
                        Err(fault) => return Err(fault),
                    }
                }
                note(store, lease, &id, actor_reason(error)).await?;
                return Ok(None);
            }
        };
        let different_lineage =
            authority.receipt().lineage_root_id != target.binding.attempt.lineage_root_id;
        let frozen_target = target.clone();
        let frozen_pin = run_pin.clone();
        let frozen_bridge = bridge_pin.clone();
        let result = stored_managed(store, lease, move |store| {
            store.egress_freeze(
                &frozen_target,
                &authority,
                &frozen_pin,
                &frozen_bridge,
                &audience,
            )
        })
        .await;
        match result {
            Ok(frozen) => Ok(Some(frozen)),
            Err(error) => {
                let key = id.clone();
                let close = request_id.clone();
                let _ = stored_managed(store, lease, move |store| {
                    store.egress_reset_probe(&key, &close)
                })
                .await;
                if error == Fault::Forbidden && different_lineage {
                    let key = id.clone();
                    stored_managed(store, lease, move |store| {
                        store.egress_not_delivered(&key, "different_lineage")
                    })
                    .await?;
                } else if error == Fault::Forbidden {
                    note(store, lease, &id, "binding_unavailable").await?;
                } else if error == Fault::Stale {
                    let key = id.clone();
                    let check_prefix = prefix.clone();
                    let latest = stored_managed(store, lease, move |store| {
                        store.egress_target(&key, &check_prefix)
                    })
                    .await;
                    if matches!(latest, Err(Fault::Stale)) {
                        let key = id.clone();
                        stored_managed(store, lease, move |store| {
                            store.egress_not_delivered(&key, "member_removed")
                        })
                        .await?;
                    } else {
                        note(store, lease, &id, "binding_unavailable").await?;
                    }
                } else {
                    note(store, lease, &id, "route_unavailable").await?;
                }
                Ok(None)
            }
        }
    }

    /// The only repeatable send is a positively known-unsent original target.
    pub(super) async fn publish<C: OwnerClient + Clone + 'static>(
        store: &SharedStore,
        lease: &ManagedLease,
        frozen: Frozen,
        client: C,
    ) -> Result<(), Fault> {
        let id = frozen.seed.effect_id.clone();
        require_effect_lease(lease, &id)?;
        let check = client.clone();
        let expected = frozen.bridge_pin.route.component_store_id.clone();
        let capability_lease = lease.clone();
        let caps = tokio::task::spawn_blocking(move || {
            let _lease = capability_lease;
            check.capabilities(&expected)
        })
        .await
        .map_err(|_| Fault::Unavailable)?;
        if let Err(error) = caps {
            return note(
                store,
                lease,
                &id,
                if error == OwnerFailure::Unknown {
                    "route_unavailable"
                } else {
                    bridge_reason(error)
                },
            )
            .await;
        }
        let key = id.clone();
        let (frozen, dispatch) =
            match stored_managed(store, lease, move |store| store.egress_begin_publish(&key)).await
            {
                Ok(value) => value,
                Err(Fault::Stale) => return Ok(()),
                Err(error) => return Err(error),
            };
        let worker = client.clone();
        let sent = frozen.clone();
        let correlation = dispatch.clone();
        let bridge_lease = lease.clone();
        let result = match tokio::task::spawn_blocking(move || {
            let _lease = bridge_lease;
            worker.publish(&correlation, &sent)
        })
        .await
        {
            Ok(value) => value,
            Err(_) => {
                note(store, lease, &id, "outcome_unknown").await?;
                return Ok(());
            }
        };
        match result {
            Ok(result) => {
                let key = id.clone();
                let correlation = dispatch.clone();
                let recorded = stored_managed(store, lease, move |store| {
                    store
                        .egress_result(&key, Some(&correlation), &result, false)
                        .map(|_| ())
                })
                .await;
                match recorded {
                    Ok(()) | Err(Fault::Stale) => {}
                    Err(Fault::Conflict | Fault::Invalid) => {
                        note(store, lease, &id, "outcome_unknown").await?
                    }
                    Err(error) => return Err(error),
                }
            }
            Err(OwnerFailure::RelaunchRequired) => {
                let key = id.clone();
                stored_managed(store, lease, move |store| {
                    store.egress_not_sent(&key, &dispatch, "relaunch_required")
                })
                .await?;
            }
            Err(OwnerFailure::NotSent(reason)) => {
                let key = id.clone();
                stored_managed(store, lease, move |store| {
                    store.egress_not_sent(&key, &dispatch, reason)
                })
                .await?;
            }
            Err(OwnerFailure::Unknown) => note(store, lease, &id, "outcome_unknown").await?,
        }
        Ok(())
    }

    /// Unknown custody is looked up or fenced, never automatically republished.
    pub(super) async fn reconcile<C: OwnerClient + Clone + 'static>(
        store: &SharedStore,
        lease: &ManagedLease,
        frozen: Frozen,
        client: C,
        abort: bool,
    ) -> Result<(), Fault> {
        reconcile_outcome(store, lease, frozen, client, abort)
            .await
            .map(|_| ())
    }

    /// E12 liveness: exact lookups with capped backoff; after
    /// `LIVENESS_LOOKUPS` non-decisive results the exact original effect is
    /// aborted. Only a durable `aborted` creates ONE new effect for the same
    /// event, in the same transaction that records it; `accepted` is delivered;
    /// uncertainty (or a successor refused for capacity) keeps retrying the
    /// same-key abort with backoff and attention.
    pub(super) async fn liveness<C: OwnerClient + Clone + 'static>(
        store: &SharedStore,
        lease: &ManagedLease,
        frozen: Frozen,
        client: C,
        state: State,
        now: i64,
    ) -> Result<(), Fault> {
        let id = frozen.seed.effect_id.clone();
        require_effect_lease(lease, &id)?;
        let key = id.clone();
        if !stored_managed(store, lease, move |store| {
            store.egress_liveness_due(&key, now)
        })
        .await?
        {
            return Ok(());
        }
        let aborting = state == State::AbortPending;
        let outcome = reconcile_outcome(store, lease, frozen, client, aborting).await?;
        let key = id.clone();
        match outcome {
            Some(State::Accepted | State::Aborted) => Ok(()),
            _ => {
                let failures = stored_managed(store, lease, move |store| {
                    store.egress_liveness_failed(&key, now)
                })
                .await?;
                if !aborting && failures >= crate::managed_egress::LIVENESS_LOOKUPS {
                    let key = id.clone();
                    match stored_managed(store, lease, move |store| {
                        store.egress_begin_liveness_abort(&key)
                    })
                    .await
                    {
                        Ok(()) | Err(Fault::Stale) => {}
                        Err(error) => return Err(error),
                    }
                }
                Ok(())
            }
        }
    }

    /// One exact lookup or abort; returns the decisive recorded state, if any.
    async fn reconcile_outcome<C: OwnerClient + Clone + 'static>(
        store: &SharedStore,
        lease: &ManagedLease,
        frozen: Frozen,
        client: C,
        abort: bool,
    ) -> Result<Option<State>, Fault> {
        let id = frozen.seed.effect_id.clone();
        require_effect_lease(lease, &id)?;
        let (request, original) = if abort {
            let key = id.clone();
            let (frozen, request) =
                stored_managed(store, lease, move |store| store.egress_begin_abort(&key)).await?;
            (request, frozen)
        } else {
            (crate::domain::id(), frozen)
        };
        let worker = client.clone();
        let call = original.clone();
        let bridge_lease = lease.clone();
        let result = match tokio::task::spawn_blocking(move || {
            let _lease = bridge_lease;
            if abort {
                worker.abort(&request, &call)
            } else {
                worker.lookup(&request, &call)
            }
        })
        .await
        {
            Ok(value) => value,
            Err(_) => {
                note(store, lease, &id, "outcome_unknown").await?;
                return Ok(None);
            }
        };
        match result {
            Ok(result) => {
                let key = id.clone();
                let recorded = stored_managed(store, lease, move |store| {
                    store.egress_result(&key, None, &result, abort)
                })
                .await;
                match recorded {
                    Ok(state @ (State::Accepted | State::Aborted)) => return Ok(Some(state)),
                    // Unavailable: the E12 successor was refused (capacity), so
                    // nothing committed; the same-key abort is retried later.
                    Ok(_) | Err(Fault::Stale | Fault::Unavailable) => {}
                    Err(Fault::Conflict | Fault::Invalid) => {
                        note(store, lease, &id, "outcome_unknown").await?
                    }
                    Err(error) => return Err(error),
                }
            }
            Err(OwnerFailure::RelaunchRequired) => {
                note(store, lease, &id, "relaunch_required").await?
            }
            Err(_) => note(store, lease, &id, "outcome_unknown").await?,
        }
        Ok(None)
    }

    /// A retired scope is compacted only after all local effects are terminal.
    pub(super) async fn scope<C: OwnerClient + Clone + 'static>(
        store: &SharedStore,
        lease: &ManagedLease,
        plan: crate::managed_egress::ScopePlan,
        client: C,
    ) -> Result<(), Fault> {
        if lease._inner.work != ManagedWork::EgressScope(plan.producer_scope.clone()) {
            return Err(Fault::Unauthorized);
        }
        let expected = plan.bridge_pin.route.component_store_id.clone();
        let check = client.clone();
        let check_lease = lease.clone();
        if !matches!(
            tokio::task::spawn_blocking(move || {
                let _lease = check_lease;
                check.capabilities(&expected)
            })
            .await,
            Ok(Ok(()))
        ) {
            return Ok(());
        }
        let work = client.clone();
        let scoped = plan.clone();
        let scoped_lease = lease.clone();
        if plan.needs_retire {
            let result = tokio::task::spawn_blocking(move || {
                let _lease = scoped_lease;
                work.retire(&scoped.retire_request_id, &scoped)
            })
            .await;
            if let Ok(Ok(receipt)) = result {
                match stored_managed(store, lease, move |store| {
                    store.egress_scope_retired(&plan, &receipt)
                })
                .await
                {
                    Ok(()) | Err(Fault::Stale | Fault::Conflict | Fault::Invalid) => {}
                    Err(error) => return Err(error),
                }
            }
        } else {
            let result = tokio::task::spawn_blocking(move || {
                let _lease = scoped_lease;
                work.compact(&crate::domain::id(), &scoped)
            })
            .await;
            if let Ok(Ok(receipt)) = result {
                match stored_managed(store, lease, move |store| {
                    store.egress_scope_compacted(&plan, &receipt)
                })
                .await
                {
                    Ok(()) | Err(Fault::Stale | Fault::Conflict | Fault::Invalid) => {}
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(())
    }

    fn unix_now() -> Result<i64, Fault> {
        i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| Fault::Unavailable)?
                .as_secs(),
        )
        .map_err(|_| Fault::Unavailable)
    }

    /// One managed effect; disabling new egress never turns uncertain recovery into a resend.
    pub(super) async fn drive(
        store: &SharedStore,
        config: &Config,
        effect: &Effect,
        activity: &Arc<ManagedActivity>,
    ) -> Result<(), Fault> {
        let id = effect.effect_id.clone();
        let Some(lease) = activity.acquire(ManagedWork::Egress(id.clone()))? else {
            return Ok(());
        };
        let key = id.clone();
        let state = stored_managed(store, &lease, move |store| store.egress_state(&key)).await?;
        let Some(mut state) = state else {
            // Pre-v10 unknown work has no event-bound seed and is never published on the new route.
            return settle(
                store,
                id,
                if effect.state == "inflight" {
                    "refused"
                } else {
                    "unknown"
                },
            )
            .await;
        };
        let transport = config.managed_run_transport.as_ref();
        if state == State::Pending {
            // E14(d): a republished successor waits out its durable backoff.
            let now = unix_now()?;
            let key = id.clone();
            if !stored_managed(store, &lease, move |store| {
                store.egress_liveness_due(&key, now)
            })
            .await?
            {
                return Ok(());
            }
            let Some(transport) = transport.filter(|value| value.egress_enabled) else {
                return note(store, &lease, &id, "route_unavailable").await;
            };
            let prefix = transport
                .producer_scope_prefix
                .clone()
                .ok_or(Fault::Invalid)?;
            let key = id.clone();
            let check_prefix = prefix.clone();
            let target = match stored_managed(store, &lease, move |store| {
                store.egress_target(&key, &check_prefix)
            })
            .await
            {
                Ok(target) => target,
                Err(Fault::Stale) => {
                    let key = id.clone();
                    return stored_managed(store, &lease, move |store| {
                        store.egress_not_delivered(&key, "member_removed")
                    })
                    .await;
                }
                Err(_) => return note(store, &lease, &id, "binding_unavailable").await,
            };
            let run = match RunPeer::from_config(config, &target.binding.pool_store_id) {
                Ok(run) => run,
                Err(_) => return note(store, &lease, &id, "route_unavailable").await,
            };
            if run.route != target.binding.run_route
                || run.bridge_route != target.binding.bridge_route
            {
                return note(store, &lease, &id, "route_unavailable").await;
            }
            let cfg = config.clone();
            let route = target.binding.bridge_route.clone();
            let (bridge, bridge_pin) = match tokio::task::spawn_blocking(move || {
                crate::managed_bridge::SdkBridge::capture(&cfg, route)
            })
            .await
            .map_err(|_| Fault::Unavailable)?
            {
                Ok(value) => value,
                Err(_) => return note(store, &lease, &id, "route_unavailable").await,
            };
            if let Some(frozen) = freeze_target(
                store,
                &lease,
                target,
                prefix,
                &run,
                bridge_pin,
                config.bridge_audience.clone(),
            )
            .await?
            {
                return publish(store, &lease, frozen, bridge).await;
            }
            return Ok(());
        }
        if state == State::Publishing {
            note(store, &lease, &id, "outcome_unknown").await?;
            state = State::Unknown;
        }
        if matches!(
            state,
            State::Accepted | State::Aborted | State::NotDelivered
        ) {
            return Ok(());
        }
        let key = id.clone();
        let frozen = stored_managed(store, &lease, move |store| store.egress_frozen(&key)).await?;
        let cfg = config.clone();
        let pin = frozen.bridge_pin.clone();
        let bridge = match tokio::task::spawn_blocking(move || {
            crate::managed_bridge::SdkBridge::recover(&cfg, &pin)
        })
        .await
        .map_err(|_| Fault::Unavailable)?
        {
            Ok(value) => value,
            Err(_) => return note(store, &lease, &id, "route_unavailable").await,
        };
        let key = id.clone();
        let draining = stored_managed(store, &lease, move |store| {
            store.egress_scope_draining(&key)
        })
        .await?;
        if matches!(state, State::Unknown | State::AbortPending) && !draining {
            let now = unix_now()?;
            return liveness(store, &lease, frozen, bridge, state, now).await;
        }
        if matches!(state, State::Unknown | State::AbortPending)
            || (state == State::KnownUnsent && draining && !frozen.seed.final_notice)
        {
            return reconcile(
                store,
                &lease,
                frozen,
                bridge,
                state == State::AbortPending || draining,
            )
            .await;
        }
        if !transport.is_some_and(|value| {
            value.egress_enabled
                && value
                    .producer_scope_prefix
                    .as_deref()
                    .is_some_and(|prefix| frozen.seed.producer_scope.starts_with(prefix))
        }) {
            return note(store, &lease, &id, "route_unavailable").await;
        }
        let configured =
            match RunPeer::from_config(config, &frozen.intent.target_binding.pool_store_id) {
                Ok(value) => value,
                Err(_) => return note(store, &lease, &id, "route_unavailable").await,
            };
        if configured.endpoint_pin() != frozen.run_pin.endpoint() {
            return note(store, &lease, &id, "route_unavailable").await;
        }
        publish(store, &lease, frozen, bridge).await
    }
}

/// Retire one settled scope per cycle; unresolved effects never block other scopes.
async fn recover_egress_scope(
    config: &Config,
    store: &SharedStore,
    activity: &Arc<ManagedActivity>,
) -> Result<(), Fault> {
    let Some(transport) = config.managed_run_transport.as_ref() else {
        return Ok(());
    };
    let Some((scope, state)) = stored(store, |store| store.egress_next_scope()).await? else {
        return Ok(());
    };
    if state == "draining" && !transport.egress_enabled {
        return Ok(());
    }
    let Some(lease) = activity.acquire(ManagedWork::EgressScope(scope.clone()))? else {
        return Ok(());
    };
    let source = stored_managed(store, &lease, |store| store.managed_store_id()).await?;
    if transport.egress_enabled
        && transport.producer_scope_prefix.as_deref() != Some(format!("pool/{source}/").as_str())
    {
        return Ok(());
    }
    let run = match crate::managed_run::RunPeer::from_config(config, &source) {
        Ok(value) => value,
        Err(_) => return Ok(()),
    };
    let cfg = config.clone();
    let route = run.bridge_route.clone();
    let (_, pin) = match tokio::task::spawn_blocking(move || {
        crate::managed_bridge::SdkBridge::capture(&cfg, route)
    })
    .await
    {
        Ok(Ok(value)) => value,
        _ => return Ok(()),
    };
    let pin_for_store = pin.clone();
    let endpoint = run.endpoint_pin();
    let pool_route = run.pool_route.clone();
    if let Err(error) = stored_managed(store, &lease, move |store| {
        store.managed_pin_routes(&pin_for_store, &endpoint, &pool_route)
    })
    .await
    {
        if error == Fault::Conflict {
            stale_route_pin();
        }
        return Ok(());
    }
    let scope_id = scope.clone();
    let pin_for_store = pin.clone();
    let audience = config.bridge_audience.clone();
    let plan = match stored_managed(store, &lease, move |store| {
        store.egress_prepare_scope(&scope_id, &pin_for_store, &audience)
    })
    .await
    {
        Ok(value) => value,
        Err(_) => return Ok(()),
    };
    if config.bridge_audience != plan.audience {
        return Ok(());
    }
    let cfg = config.clone();
    let original = plan.bridge_pin.clone();
    let client = match tokio::task::spawn_blocking(move || {
        crate::managed_bridge::SdkBridge::recover(&cfg, &original)
    })
    .await
    {
        Ok(Ok(client)) => client,
        _ => return Ok(()),
    };
    managed_egress_dispatch::scope(store, &lease, plan, client).await
}

/// Native Run deliveries never fall through to the legacy Bridge route.
async fn dispatch_effect(
    store: &SharedStore,
    config: &Config,
    effect_value: Effect,
    reconcile: bool,
    activity: &Arc<ManagedActivity>,
) -> Result<(), Fault> {
    if matches!(effect_value.work, Work::Deliver { .. }) && effect_value.member_id.is_some() {
        let id = effect_value.effect_id.clone();
        let managed = stored(store, move |store| {
            Ok(store
                .effect_binding(&id)?
                .is_some_and(|(binding, _)| binding.run_id.is_some()))
        })
        .await?;
        if managed {
            return managed_egress_dispatch::drive(store, config, &effect_value, activity).await;
        }
    }
    effect(store, config, effect_value, reconcile).await
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
    if config
        .managed_run_transport
        .as_ref()
        .is_some_and(|transport| transport.frontend_enabled)
    {
        return crate::managed_session::frontend(command, original_meta, &config).await;
    }
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

/// One authenticated managed frontend session, with all remote operations outside SQLite locks.
async fn managed_session(
    stream: &mut UnixStream,
    config: &Config,
    store: &SharedStore,
    activity: &Arc<ManagedActivity>,
    begin: crate::managed_session::Begin,
) -> Result<(), Fault> {
    let transport = config
        .managed_run_transport
        .as_ref()
        .ok_or(Fault::Unavailable)?;
    if !transport.frontend_enabled || begin.version != 1 {
        return Err(Fault::Unavailable);
    }
    match &begin.proof {
        bridge_sdk::bridge_protocol::CallEvidence::Native {
            host:
                bridge_sdk::bridge_protocol::Host::Codex | bridge_sdk::bridge_protocol::Host::ClaudeCode,
            ..
        } => {}
        _ => return Err(Fault::Unauthorized),
    }
    let (command, normalized) = crate::managed_codec::normalize_command(begin.command.clone())?;
    // Owner operations never run under participant authority. A managed join is
    // admitted only by the P3 enrollment gate inside the domain CAS.
    if matches!(
        command,
        Command::Start(_)
            | Command::StartBatch(_)
            | Command::Replace(_)
            | Command::EnrollmentGet(_)
            | Command::EnrollmentResolve(_)
    ) || matches!(&command, Command::Get(get) if get.wait_seconds > 0.0)
    {
        return Err(Fault::Unavailable);
    }
    let route = crate::managed_state::Route {
        component_store_id: transport.bridge_store_id.clone(),
        route_id: transport.bridge_route_id.clone(),
        worker_uid: config.expected_uid,
    };
    let capture_config = config.clone();
    let capture_route = route.clone();
    let (bridge, bridge_pin) = tokio::task::spawn_blocking(move || {
        crate::managed_bridge::SdkBridge::capture(&capture_config, capture_route)
    })
    .await
    .map_err(|_| Fault::Unavailable)??;
    if bridge_pin != begin.bridge_pin {
        return Err(Fault::Conflict);
    }
    let Some(lease) = activity.acquire(ManagedWork::Bootstrap(begin.bootstrap_id.clone()))? else {
        return Err(Fault::Unavailable);
    };
    let store_id = stored_managed(store, &lease, |store| store.managed_store_id()).await?;
    let peer = crate::managed_run::RunPeer::from_config(config, &store_id)
        .map_err(|_| Fault::Unavailable)?;
    let services = managed_dispatch::LiveSessionClient {
        config: config.clone(),
        peer,
        bridge,
    };
    managed_session_core(
        stream, config, store, activity, begin, command, normalized, bridge_pin, lease, services,
    )
    .await
}

#[allow(
    clippy::too_many_arguments,
    reason = "Authenticated session state and fixed service endpoints"
)]
async fn managed_session_core<S: managed_dispatch::SessionClient>(
    stream: &mut UnixStream,
    config: &Config,
    store: &SharedStore,
    activity: &Arc<ManagedActivity>,
    begin: crate::managed_session::Begin,
    command: Command,
    normalized: serde_json::Value,
    bridge_pin: crate::managed_bridge::BridgePin,
    lease: ManagedLease,
    services: S,
) -> Result<(), Fault> {
    use crate::managed_session::{ClientFrame, FrozenContext, ServerFrame};
    let transport = config
        .managed_run_transport
        .as_ref()
        .ok_or(Fault::Unavailable)?;
    let route = bridge_pin.route.clone();
    let endpoint = services.endpoint();
    let pool_route = services.pool_route();
    let persisted_pin = bridge_pin.clone();
    stored_managed(store, &lease, move |store| {
        store.managed_pin_routes(&persisted_pin, &endpoint, &pool_route)
    })
    .await
    .inspect_err(|error| {
        if *error == Fault::Conflict {
            stale_route_pin();
        }
    })?;
    crate::managed_session::send(stream, &ServerFrame::Ready).await?;
    let epoch = match crate::managed_session::receive::<ClientFrame>(stream).await? {
        ClientFrame::Epoch { issuer_epoch }
            if !issuer_epoch.is_empty()
                && issuer_epoch.len() <= 256
                && !issuer_epoch.chars().any(char::is_control) =>
        {
            issuer_epoch
        }
        _ => return Err(Fault::Invalid),
    };
    let bootstrap_id = begin.bootstrap_id.clone();
    let invocation = begin.invocation_key.clone();
    let epoch_for_store = epoch.clone();
    let command_for_store = command.clone();
    let proof_for_store = begin.proof.clone();
    let pin_for_store = bridge_pin.clone();
    let (namespace, dispatch) = stored_managed(store, &lease, move |store| {
        store.managed_begin_bootstrap(
            &bootstrap_id,
            &invocation,
            &epoch_for_store,
            &command_for_store,
            &proof_for_store,
            &pin_for_store,
        )
    })
    .await?;
    crate::managed_session::send(stream, &ServerFrame::Reserved).await?;
    let prepared = match crate::managed_session::receive::<ClientFrame>(stream).await? {
        ClientFrame::StaleEpoch => {
            stored_managed(store, &lease, move |store| {
                store.managed_stale_bootstrap(dispatch)
            })
            .await?;
            crate::managed_session::send(stream, &ServerFrame::RetryEpoch).await?;
            return Ok(());
        }
        ClientFrame::Prepared {
            store_id,
            bridge_context_ref,
            invocation_key,
            expires_at_ms,
        } if expires_at_ms > 0 => crate::managed_bridge::Prepared {
            store_id,
            bridge_context_ref,
            invocation_key,
            expires_at_ms,
        },
        _ => return Err(Fault::Invalid),
    };
    let observation_ref = prepared.bridge_context_ref.clone();
    let pin_for_store = bridge_pin.clone();
    stored_managed(store, &lease, move |store| {
        store.managed_record_bootstrap_ref(dispatch, &prepared, &pin_for_store)
    })
    .await?;
    let run_pin = services.current_pin().await?;
    let ingress = crate::managed_run::IngressInput {
        bridge_route: route.clone(),
        producer: config.bridge_producer_id.clone(),
        observation_ref: observation_ref.clone(),
        invocation_key: begin.invocation_key.clone(),
        request_id: crate::domain::id(),
        transport_id: crate::domain::id(),
    };
    let initial = managed_dispatch::ingress(
        store,
        activity,
        &lease,
        begin.bootstrap_id.clone(),
        run_pin.clone(),
        ingress,
        &services,
    )
    .await?;
    let context_id = crate::domain::id();
    let intent_id = crate::domain::id();
    let nonce = crate::domain::id();
    let registration_id = crate::domain::id();
    let command_for_store = command.clone();
    let route_for_store = route.clone();
    let producer = config.bridge_producer_id.clone();
    let audience = config.bridge_audience.clone();
    let invocation = begin.invocation_key.clone();
    let context_for_store = context_id.clone();
    let intent_for_store = intent_id.clone();
    let bootstrap_for_store = begin.bootstrap_id.clone();
    let registration_for_store = registration_id.clone();
    let pin_for_store = bridge_pin.clone();
    let (context, digest, binding) = stored_managed(store, &lease, move |store| {
        let binding = store.managed_select_ingress_binding(
            &initial,
            &route_for_store,
            &producer,
            &command_for_store,
        )?;
        let context = crate::managed_state::SecurityContext {
            version: 1,
            command_schema: "pool-command-v1".into(),
            pool_store_id: binding.pool_store_id.clone(),
            audience,
            producer,
            intent_id: intent_for_store,
            invocation_key: invocation,
            nonce,
            bindings: vec![binding.clone()],
        };
        let digest = store.managed_prepare_context(
            &context_for_store,
            &namespace,
            &bootstrap_for_store,
            &command_for_store,
            &context,
            &initial,
            &registration_for_store,
            &pin_for_store,
        )?;
        Ok((context, digest, binding))
    })
    .await?;
    crate::managed_session::send(
        stream,
        &ServerFrame::Context(Box::new(FrozenContext {
            context_id: context_id.clone(),
            registration_request_id: registration_id,
            command: normalized,
            context: context.clone(),
            security_digest: digest.clone(),
        })),
    )
    .await?;
    let assertion = match crate::managed_session::receive::<ClientFrame>(stream).await? {
        ClientFrame::Execute { assertion_key } => assertion_key,
        _ => return Err(Fault::Invalid),
    };
    let context_for_store = context_id.clone();
    let intent_for_store = intent_id.clone();
    let digest_for_store = digest.clone();
    let pin_for_store = bridge_pin.clone();
    stored_managed(store, &lease, move |store| {
        store.managed_mark_consume(
            &context_for_store,
            &intent_for_store,
            &digest_for_store,
            &pin_for_store,
        )
    })
    .await?;
    let consume_services = services.clone();
    let consume_pin = bridge_pin.clone();
    let consume_intent = intent_id.clone();
    let consume_invocation = begin.invocation_key.clone();
    let consume_digest = digest.clone();
    let consume_command = command.clone();
    let consume_epoch = epoch.clone();
    let consume_audience = config.bridge_audience.clone();
    let server = transport.mcp_server.clone().ok_or(Fault::Invalid)?;
    let consume_server = server.clone();
    let bridge_lease = lease.clone();
    let consumed = tokio::task::spawn_blocking(move || {
        let _lease = bridge_lease;
        let key = crate::managed_bridge::ConsumeKey {
            abort_request_id: "unused",
            expected_store_id: &consume_pin.route.component_store_id,
            producer: &consume_pin.producer,
            consume_request_id: &consume_intent,
            invocation_key: &consume_invocation,
            security_digest: &consume_digest,
            audience: &consume_audience,
        };
        consume_services.consume(
            &key,
            &assertion,
            &consume_server,
            &consume_command,
            &consume_epoch,
        )
    })
    .await
    .map_err(|_| Fault::Unavailable)?
    .map_err(crate::managed_bridge::fault)?;
    let stored_consumed = consumed.clone();
    let context_for_store = context_id.clone();
    let intent_for_store = intent_id.clone();
    let invocation_for_store = begin.invocation_key.clone();
    let digest_for_store = digest.clone();
    let command_for_store = command.clone();
    let epoch_for_store = epoch.clone();
    let audience_for_store = config.bridge_audience.clone();
    let pin_for_store = bridge_pin.clone();
    stored_managed(store, &lease, move |store| {
        let key = crate::managed_bridge::ConsumeKey {
            abort_request_id: "unused",
            expected_store_id: &pin_for_store.route.component_store_id,
            producer: &pin_for_store.producer,
            consume_request_id: &intent_for_store,
            invocation_key: &invocation_for_store,
            security_digest: &digest_for_store,
            audience: &audience_for_store,
        };
        store.managed_record_consumption(
            &context_for_store,
            &key,
            &stored_consumed,
            &server,
            &command_for_store,
            &epoch_for_store,
            &pin_for_store,
        )
    })
    .await?;
    let fresh = crate::managed_run::IngressInput {
        bridge_route: route,
        producer: config.bridge_producer_id.clone(),
        observation_ref,
        invocation_key: begin.invocation_key,
        request_id: crate::domain::id(),
        transport_id: crate::domain::id(),
    };
    let authority = managed_dispatch::ingress(
        store,
        activity,
        &lease,
        begin.bootstrap_id.clone(),
        run_pin,
        fresh,
        &services,
    )
    .await?;
    let result = if matches!(command, Command::Get(_) | Command::List(_)) {
        managed_dispatch::read(
            store,
            activity,
            &lease,
            managed_dispatch::Read {
                bootstrap_id: begin.bootstrap_id,
                context_id,
                command,
                digest,
                authorities: vec![authority],
                consumed,
            },
        )
        .await
    } else {
        let change = command.change().ok_or(Fault::Invalid)?;
        let pending_pool = change.pool_id.clone();
        let pending_key = change.request_key.clone();
        let request = managed_dispatch::Mutation {
            bootstrap_id: begin.bootstrap_id,
            context_id,
            intent_id,
            member_id: binding.member_id,
            command,
            digest,
            authority,
            consumed,
            pool_route: services.pool_route(),
        };
        match managed_dispatch::mutation(store, activity, &lease, request, &services).await {
            Ok(crate::managed_state::IntentReservation::Committed(receipt)) => {
                serde_json::from_str(&receipt).map_err(|_| Fault::Internal)
            }
            Ok(crate::managed_state::IntentReservation::Pending) => Ok(Reply::Pending {
                pool_id: pending_pool,
                request_key: pending_key,
            }),
            Ok(crate::managed_state::IntentReservation::Aborted(_)) => Err(Fault::Unavailable),
            Ok(crate::managed_state::IntentReservation::Created) => Err(Fault::Internal),
            Err(error) => Err(error),
        }
    };
    crate::managed_session::send(stream, &ServerFrame::Finished(result)).await
}

/// Authenticates and executes exactly one private frame, then closes its connection.
/// Every native replay consumes current evidence; the separate owner ingress can only project reads.
async fn connection(
    mut stream: UnixStream,
    config: Config,
    store: SharedStore,
    activity: Arc<ManagedActivity>,
    waits: Arc<Semaphore>,
    stopped: watch::Receiver<bool>,
) -> Result<(), Fault> {
    if stream.peer_cred().map_err(|_| Fault::Unauthorized)?.uid() != config.expected_uid {
        return Err(Fault::Unauthorized);
    }
    let mut wait_expiry = None;
    enum Special {
        Owner(crate::observer::Envelope),
        Managed(serde_json::Value),
        Handled,
    }
    let result = async {
        let bytes = tokio::time::timeout(EXCHANGE_TIMEOUT, integrations::read_frame(&mut stream))
            .await
            .map_err(|_| Fault::Unavailable)??;
        let value = crate::managed_codec::parse_raw(&bytes)?;
        if value.get("managed_begin").is_some() {
            let envelope: crate::managed_session::BeginEnvelope =
                serde_json::from_value(value).map_err(|_| Fault::Invalid)?;
            verify_managed_peer(&stream, config.expected_uid).await?;
            let result = managed_session(
                &mut stream,
                &config,
                &store,
                &activity,
                envelope.managed_begin,
            )
            .await;
            if let Err(error) = result {
                let _ = crate::managed_session::send(
                    &mut stream,
                    &crate::managed_session::ServerFrame::Failure(error),
                )
                .await;
            }
            return Ok(Err(Special::Handled));
        }
        if value.get("observer_credential").is_some() || value.get("observe").is_some() {
            return Ok::<_, Fault>(Err(Special::Owner(
                owner_observation(&bytes, &config, &store).await,
            )));
        }
        if value.get("method").is_some() {
            if bytes.len() >= MAX_FRAME {
                return Ok(Err(Special::Managed(crate::managed_ingress::refused())));
            }
            let managed = async {
                let request = crate::managed_ingress::Request::parse(value)?;
                let pid = stream
                    .peer_cred()
                    .map_err(|_| Fault::Unauthorized)?
                    .pid()
                    .ok_or(Fault::Unauthorized)?;
                let pid = u32::try_from(pid).map_err(|_| Fault::Unauthorized)?;
                let verified_config = config.clone();
                let (request, authorized) = tokio::task::spawn_blocking(move || {
                    let authorized = request.authenticate(&verified_config, pid).is_ok();
                    (request, authorized)
                })
                .await
                .map_err(|_| Fault::Unavailable)?;
                if !authorized {
                    return Ok(request.refused());
                }
                let request_config = config.clone();
                stored(&store, move |store| {
                    Ok(request.execute(&request_config, store))
                })
                .await
            }
            .await
            .unwrap_or_else(|_| crate::managed_ingress::refused());
            return Ok(Err(Special::Managed(managed)));
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
        Ok(Err(Special::Handled)) => return Ok(()),
        Ok(Err(Special::Owner(envelope))) => {
            let bytes = crate::observer::encode(&envelope).or_else(|error| {
                crate::observer::encode(&crate::observer::Envelope::failure(&envelope.kind, error))
            })?;
            return tokio::time::timeout(EXCHANGE_TIMEOUT, stream.write_all(&bytes))
                .await
                .map_err(|_| Fault::Unavailable)?
                .map_err(|_| Fault::Unavailable);
        }
        Ok(Err(Special::Managed(value))) => {
            let mut bytes = serde_json::to_vec(&value).map_err(|_| Fault::Internal)?;
            if bytes.len() >= MAX_FRAME {
                return Err(Fault::Unavailable);
            }
            bytes.push(b'\n');
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

/// The legacy Bridge-only path has no Run attempt proof, so it never joins a
/// Run-started member. P3 enrollees join only through the managed session,
/// where `managed_enrollment::join_gate` checks the owner receipt, the
/// qualified enrollment binding, the fresh P1 proof and the pending CAS.
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

/// The configured Bridge or Run pin no longer matches the stored route pin, typically after
/// an upgrade moved an executable. Managed work on that route is refused, everything else
/// continues, and the operator action is named once per resident process.
fn stale_route_pin() {
    static REPORTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if !REPORTED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        eprintln!(
            "resident: managed work refused (Conflict): the configured Bridge or Run executable pin differs from the stored route pin; stop the resident, run `agent-pool repin --config <config>`, then restart it; other work continues"
        );
    }
}

/// Verify both configured services and atomically re-pin an existing, exclusively held store.
/// Only executable paths, build digests and the credential digest may change. Each candidate
/// executable is proved on disk, then its live peer through the same pinned capability
/// exchanges used by admission, before one transaction records the new generations.
pub async fn repin(config_path: &Path) -> Result<(i64, i64), Fault> {
    let config = Config::load(config_path)?;
    integrations::own_uid(config.expected_uid)?;
    private_parent(&config.database_path, config.expected_uid)?;
    private_file(&config.database_path, config.expected_uid)?;
    let lock_path = config.database_path.with_extension("lock");
    if fs::symlink_metadata(&lock_path).is_ok() {
        private_file(&lock_path, config.expected_uid)?;
    }
    let mut store = Store::open(&config.database_path)?;
    let store_id = store.managed_store_id()?;
    let peer =
        crate::managed_run::RunPeer::from_config(&config, &store_id).map_err(|_| Fault::Invalid)?;
    let route = peer.bridge_route.clone();
    let capture_config = config.clone();
    let (bridge, bridge_pin) = tokio::task::spawn_blocking(move || {
        crate::managed_bridge::SdkBridge::capture(&capture_config, route)
    })
    .await
    .map_err(|_| Fault::Unavailable)??;
    let run_pin = peer.endpoint_pin();
    store
        .managed_repin_routes(&bridge_pin, &run_pin, &peer.pool_route, false)
        .inspect_err(|error| {
            if *error == Fault::Conflict {
                eprintln!(
                    "repin: a configured route, socket, producer or credential file differs from the pinned one; only executable paths and digests can be re-pinned; no pin was changed"
                );
            }
        })?;
    let uid = config.expected_uid;
    let candidates = [
        (
            "Bridge server",
            bridge_pin.server_executable.clone(),
            bridge_pin.server_sha256.clone(),
        ),
        (
            "Run",
            run_pin.executable.clone(),
            run_pin.executable_sha256.clone(),
        ),
    ];
    tokio::task::spawn_blocking(move || {
        for (name, path, sha256) in candidates {
            crate::config::trusted_executable(&path, &sha256, uid).map_err(|reason| {
                eprintln!(
                    "repin: the configured {name} executable is not trusted ({reason}); no pin was changed"
                );
                Fault::Unauthorized
            })?;
        }
        Ok::<(), Fault>(())
    })
    .await
    .map_err(|_| Fault::Unavailable)??;
    let expected = bridge_pin.route.component_store_id.clone();
    tokio::task::spawn_blocking(move || crate::managed_bridge::discover(&bridge, &expected))
        .await
        .map_err(|_| Fault::Unavailable)?
        .map_err(|error| {
            eprintln!(
                "repin: Bridge capability/issuer discovery failed on the configured route ({}); no pin was changed",
                match error {
                    crate::managed_bridge::BridgeFailure::RelaunchRequired => "relaunch_required",
                    crate::managed_bridge::BridgeFailure::Refused => "peer_not_authorized",
                    _ => "route_unavailable",
                }
            );
            crate::managed_bridge::fault(error)
        })?;
    peer.current_pin("attempt_current_ingress_v1")
        .await
        .map_err(|_| {
            eprintln!(
                "repin: Run attempt capability discovery failed on the configured route (route_unavailable); no pin was changed"
            );
            Fault::Unavailable
        })?;
    store.managed_repin_routes(&bridge_pin, &run_pin, &peer.pool_route, true)
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
    let mut opened = tokio::task::spawn_blocking(move || Store::open(&database_path))
        .await
        .map_err(|_| Fault::Internal)??;
    if config
        .managed_run_transport
        .as_ref()
        .is_some_and(|transport| transport.enrollment_enabled)
    {
        let pool_store = opened.managed_store_id()?;
        opened.configure_enrollment(Some(
            enrollment_dispatch::configured_route(&config, &pool_store).ok_or(Fault::Invalid)?,
        ));
    }
    let store = Arc::new(Mutex::new(opened));
    let (listener, _guard) = listener(&config).await?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|_| Fault::Unavailable)?;
    let (stop, stopped) = watch::channel(false);
    let managed_activity = Arc::new(ManagedActivity::default());
    let mut worker = tokio::spawn(work(
        config.clone(),
        Arc::clone(&store),
        stopped.clone(),
        Arc::clone(&managed_activity),
    ));
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
                let activity = Arc::clone(&managed_activity);
                let waits = Arc::clone(&waits);
                let stopped = stopped.clone();
                connections.spawn(async move { let _permit = permit; connection(stream, config, store, activity, waits, stopped).await });
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
            if effect.member_id.is_some() {
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
                    let recorded = stored(store, move |store| {
                        store.record_run_admission(&effect_id, &agent_id, sequence)
                    })
                    .await?;
                    if recorded == Admitted::ReconciliationNeeded {
                        // The completed pool retained the receipt; the effect is terminal.
                        return Ok(());
                    }
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
                            match record_batch(store, &effect.effect_id, Some(expected), admissions)
                                .await?
                            {
                                Admitted::Installed => {
                                    settle(store, effect.effect_id, "accepted").await
                                }
                                Admitted::ReconciliationNeeded => Ok(()),
                            }
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
                        return match record_batch(
                            store,
                            &effect.effect_id,
                            expected_store_id.as_deref(),
                            admissions,
                        )
                        .await?
                        {
                            Admitted::Installed => {
                                settle(store, effect.effect_id, "accepted").await
                            }
                            Admitted::ReconciliationNeeded => Ok(()),
                        };
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
                    match record_batch(
                        store,
                        &effect.effect_id,
                        expected_store_id.as_deref(),
                        admissions,
                    )
                    .await?
                    {
                        Admitted::Installed => "accepted",
                        Admitted::ReconciliationNeeded => return Ok(()),
                    }
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
                // Installed, or retained after completion: the effect is settled either way.
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
/// After pool completion the receipt is retained and the effect is already terminal.
async fn record_replacement(
    store: &SharedStore,
    effect_id: &str,
    token: &str,
    expected_store: &str,
    mut admissions: Vec<integrations::BatchAdmission>,
) -> Result<Admitted, Fault> {
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
/// After pool completion the receipt is retained instead and the effect is already terminal.
async fn record_batch(
    store: &SharedStore,
    effect_id: &str,
    expected_store_id: Option<&str>,
    admissions: Vec<integrations::BatchAdmission>,
) -> Result<Admitted, Fault> {
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

/// Reconcile managed work only when no live caller owns its exact key.
/// Each store operation finishes before any authenticated Bridge/Run I/O begins.
async fn recover_managed(
    config: &Config,
    store: &SharedStore,
    stopped: &watch::Receiver<bool>,
    activity: &Arc<ManagedActivity>,
) -> Result<(), Fault> {
    use crate::managed_state::{BootstrapRecoveryAction, RecoveryAction};
    let bootstraps = stored(store, |store| store.managed_pending_bootstraps()).await?;
    for bootstrap in bootstraps {
        if *stopped.borrow() {
            return Ok(());
        }
        let Some(lease) = activity.acquire(ManagedWork::Bootstrap(bootstrap.clone()))? else {
            continue;
        };
        let action = stored_managed(store, &lease, move |store| {
            store.managed_stage_bootstrap(&bootstrap)
        })
        .await;
        let Ok(BootstrapRecoveryAction::BridgeAbort {
            context_id,
            pin,
            key,
        }) = action
        else {
            continue;
        };
        let cfg = config.clone();
        let bridge_lease = lease.clone();
        let (pin, key, result) = tokio::task::spawn_blocking(move || {
            let _lease = bridge_lease;
            let result = crate::managed_bridge::SdkBridge::recover(&cfg, &pin)
                .ok()
                .and_then(|bridge| {
                    crate::managed_bridge::abort_original(&bridge, &key.borrowed()).ok()
                });
            (pin, key, result)
        })
        .await
        .map_err(|_| Fault::Internal)?;
        if let Some(result) = result {
            let _ = stored_managed(store, &lease, move |store| {
                store.managed_record_bootstrap_abort(&context_id, &key, &pin, &result)
            })
            .await;
        }
    }
    let pending = stored(store, |store| store.managed_pending()).await?;
    for (id, digest) in pending {
        if *stopped.borrow() {
            return Ok(());
        }
        let Some(lease) = activity.acquire(ManagedWork::Intent(id.clone()))? else {
            continue;
        };
        let stage_id = id.clone();
        let stage_digest = digest.clone();
        let Ok(action) = stored_managed(store, &lease, move |store| {
            store.managed_stage_recovery(&stage_id, &stage_digest)
        })
        .await
        else {
            continue;
        };
        match action {
            RecoveryAction::LocallyFenced | RecoveryAction::Done => {}
            RecoveryAction::BridgeAbort {
                intent_id,
                context_id: _,
                digest,
                pin,
                key,
            } => {
                let cfg = config.clone();
                let bridge_lease = lease.clone();
                let (pin, key, result) = tokio::task::spawn_blocking(move || {
                    let _lease = bridge_lease;
                    let result = crate::managed_bridge::SdkBridge::recover(&cfg, &pin)
                        .ok()
                        .and_then(|bridge| {
                            crate::managed_bridge::abort_original(&bridge, &key.borrowed()).ok()
                        });
                    (pin, key, result)
                })
                .await
                .map_err(|_| Fault::Internal)?;
                if let Some(result) = result {
                    let _ = stored_managed(store, &lease, move |store| {
                        store.managed_record_bridge_abort(&intent_id, &digest, &key, &pin, &result)
                    })
                    .await;
                }
            }
            RecoveryAction::RunAbort {
                intent,
                outcome_digest,
            } => {
                let Ok(peer) = crate::managed_run::RunPeer::from_recovery(config, &intent) else {
                    continue;
                };
                if let Ok(result) = peer
                    .abort(
                        &crate::domain::id(),
                        &intent.intent_id,
                        &intent.security_digest,
                        &intent.pool_route,
                        Some(&outcome_digest),
                    )
                    .await
                {
                    let _ = stored_managed(store, &lease, move |store| {
                        store.managed_record_run_abort(
                            &intent.intent_id,
                            &intent.security_digest,
                            &result,
                        )
                    })
                    .await;
                }
            }
            RecoveryAction::RunSettle {
                intent,
                outcome_digest,
            } => {
                let Some(admission) = intent.admission.as_ref() else {
                    continue;
                };
                let Ok(peer) = crate::managed_run::RunPeer::from_recovery(config, &intent) else {
                    continue;
                };
                if let Ok(result) = peer
                    .settle(
                        &crate::domain::id(),
                        &admission.admission_id,
                        &intent.intent_id,
                        &intent.security_digest,
                        &outcome_digest,
                    )
                    .await
                {
                    let _ = stored_managed(store, &lease, move |store| {
                        store.managed_record_run_settlement(
                            &intent.intent_id,
                            &intent.security_digest,
                            &result,
                        )
                    })
                    .await;
                }
            }
        }
    }
    Ok(())
}

/// Retire one drained superseded issuer, retaining exact keys across errors and restarts.
async fn recover_namespace_retirement(config: &Config, store: &SharedStore) -> Result<(), Fault> {
    if config.managed_run_transport.is_none()
        || !stored(store, |store| store.managed_has_namespace_retirement_work()).await?
    {
        return Ok(());
    }
    let source = stored(store, |store| store.managed_store_id()).await?;
    let Ok(peer) = crate::managed_run::RunPeer::from_config(config, &source) else {
        return Ok(());
    };
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Fault::Unavailable)?
            .as_secs(),
    )
    .map_err(|_| Fault::Unavailable)?;
    let stage = |issuer: Option<String>| {
        let peer = peer.clone();
        async move {
            stored(store, move |store| {
                store.managed_stage_namespace_retirement(
                    &peer.endpoint_pin(),
                    &peer.pool_route,
                    &peer.bridge_route,
                    &peer.producer,
                    issuer.as_deref(),
                    now,
                )
            })
            .await
        }
    };
    let mut plan = match stage(None).await {
        Ok(plan) => plan,
        Err(_) => return Ok(()),
    };
    if plan.is_none() {
        // E11: a failed issuer discovery is durable owner attention with
        // bounded backoff; it never silently stops retirement.
        if !stored(store, move |store| store.managed_discovery_due(now)).await? {
            return Ok(());
        }
        let failed = |code: &'static str| async move {
            eprintln!("namespace retirement deferred: {code}");
            stored(store, move |store| {
                store.managed_discovery_failed(code, now)
            })
            .await
        };
        let cfg = config.clone();
        let route = peer.bridge_route.clone();
        let Ok(Ok((bridge, pin))) = tokio::task::spawn_blocking(move || {
            crate::managed_bridge::SdkBridge::capture(&cfg, route)
        })
        .await
        else {
            return failed("route_unavailable").await;
        };
        let candidate = pin.clone();
        let pinned_peer = peer.clone();
        if let Err(error) = stored(store, move |store| {
            store.managed_pin_routes(
                &candidate,
                &pinned_peer.endpoint_pin(),
                &pinned_peer.pool_route,
            )
        })
        .await
        {
            if error == Fault::Conflict {
                stale_route_pin();
            }
            return failed("route_changed").await;
        }
        let expected = pin.route.component_store_id.clone();
        let issuer = match tokio::task::spawn_blocking(move || {
            crate::managed_bridge::discover(&bridge, &expected)
        })
        .await
        {
            Ok(Ok(issuer)) => issuer,
            Ok(Err(crate::managed_bridge::BridgeFailure::RelaunchRequired)) => {
                return failed("relaunch_required").await;
            }
            _ => return failed("route_unavailable").await,
        };
        stored(store, |store| store.managed_discovery_succeeded()).await?;
        plan = stage(Some(issuer)).await.ok().flatten();
    }
    if let Some(plan) = plan {
        let retired = peer.retire_namespace(&plan).await.is_ok();
        let completed = if retired {
            let completion = plan.clone();
            stored(store, move |store| {
                store.managed_complete_namespace_retirement(&completion)
            })
            .await
            .is_ok()
        } else {
            false
        };
        if !completed {
            let failed_at = i64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|_| Fault::Unavailable)?
                    .as_secs(),
            )
            .map_err(|_| Fault::Unavailable)?;
            stored(store, move |store| {
                store.managed_defer_namespace_retirement(&plan, failed_at)
            })
            .await?;
        }
    }
    Ok(())
}

/// Unknown delivery uses status only; unknown Run admission retries the same frozen admission key.
async fn work(
    config: Config,
    store: SharedStore,
    mut stopped: watch::Receiver<bool>,
    activity: Arc<ManagedActivity>,
) -> Result<(), Fault> {
    let mut interval = tokio::time::interval(OBSERVATION_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut observation_cursor = 0;
    // P3 enrollment reconciliation: rotating cursor, backoff and a per-pass budget.
    let mut enrollment_schedule = enrollment_dispatch::Schedule::default();
    let started = std::time::Instant::now();
    // P3-C automatic settlement stays off unless Run and managed consensus routes are configured.
    let mut completion = None;
    loop {
        tokio::select! {
            biased;
            changed = stopped.changed() => { if changed.is_err() || *stopped.borrow() { return Ok(()); } }
            _ = interval.tick() => (),
        }
        recover_managed(&config, &store, &stopped, &activity).await?;
        if config.managed_run_transport.is_some() {
            let pool_store = stored(&store, |store| store.managed_store_id()).await?;
            if let Some(client) = enrollment_dispatch::Live::new(&config, &pool_store) {
                let now = started.elapsed().as_secs();
                enrollment_dispatch::reconcile(
                    &store,
                    &client,
                    &stopped,
                    &mut enrollment_schedule,
                    now,
                )
                .await?;
            }
        }
        recover_egress_scope(&config, &store, &activity).await?;
        recover_namespace_retirement(&config, &store).await?;
        if completion.is_none() {
            let pool_store = stored(&store, |store| store.managed_store_id()).await?;
            if let Some(driver) = crate::completion_saga::Driver::production(&config, &pool_store) {
                if driver.sweep(&store).await.is_ok() {
                    completion = Some(driver);
                } else {
                    let changed = stored(&store, |store| {
                        crate::completion::driver_unavailable(
                            store.completion_db(),
                            "key_unavailable",
                        )
                    })
                    .await?;
                    if changed > 0 {
                        eprintln!("completion settlement unavailable: key_unavailable");
                    }
                }
            } else {
                let reason = crate::completion_saga::Driver::unavailable_reason(&config);
                let changed = stored(&store, move |store| {
                    crate::completion::driver_unavailable(store.completion_db(), reason)
                })
                .await?;
                if changed > 0 {
                    eprintln!("completion settlement unavailable: {reason}");
                }
            }
        }
        if let Some(driver) = completion.as_mut() {
            driver.tick(&store, &stopped).await?;
        }
        for _ in 0..32 {
            if *stopped.borrow() {
                return Ok(());
            }
            let managed_enabled = config
                .managed_run_transport
                .as_ref()
                .is_some_and(|transport| transport.egress_enabled);
            let next = if managed_enabled {
                stored(&store, |store| store.next_bound_managed_egress()).await?
            } else {
                None
            };
            let next = match next {
                Some(value) => Some(value),
                None => stored(&store, |store| store.next_effect()).await?,
            };
            let Some(next) = next else {
                break;
            };
            dispatch_effect(&store, &config, next, false, &activity).await?;
        }
        let pending = stored(&store, |store| store.pending_unknown()).await?;
        for pending in pending {
            if *stopped.borrow() {
                return Ok(());
            }
            dispatch_effect(&store, &config, pending, true, &activity).await?;
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

/// Test-only entry into the resident's serial outbox worker with fresh managed activity.
#[cfg(test)]
pub(crate) async fn fixture_work(
    config: Config,
    store: SharedStore,
    stopped: watch::Receiver<bool>,
) -> Result<(), Fault> {
    work(config, store, stopped, Arc::new(ManagedActivity::default())).await
}

/// Local lifecycle checks exercise supervisor contracts without bypassing production authentication.
#[cfg(test)]
mod tests {
    use super::*;

    /// Exercise the operator entry point against isolated same-process peers, including a rejected build.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn repin_cli_authenticates_both_candidates_before_commit()
    -> Result<(), Box<dyn std::error::Error>> {
        use sha2::{Digest, Sha256};
        use tokio::io::AsyncReadExt;

        let _guard = crate::TEST_EXEC_HASH_LOCK.lock().await;
        let directory =
            tempfile::tempdir_in(std::env::var_os("TMPDIR").ok_or("task TMPDIR required")?)?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let root = &fs::canonicalize(directory.path())?;
        let uid = fs::metadata(root)?.uid();
        let bridge_socket = root.join("bridge.sock");
        let run_socket = root.join("attempt.sock");
        let bridge_listener = UnixListener::bind(&bridge_socket)?;
        let run_listener = UnixListener::bind(&run_socket)?;
        fs::set_permissions(&bridge_socket, fs::Permissions::from_mode(0o600))?;
        fs::set_permissions(&run_socket, fs::Permissions::from_mode(0o600))?;
        let credential = root.join("credential");
        fs::write(&credential, "fixture-credential")?;
        fs::set_permissions(&credential, fs::Permissions::from_mode(0o600))?;
        let executable = fs::canonicalize(std::env::current_exe()?)?;
        struct RestoreExecutableMode(PathBuf, fs::Permissions);
        impl Drop for RestoreExecutableMode {
            fn drop(&mut self) {
                let _ = fs::set_permissions(&self.0, self.1.clone());
            }
        }
        let _mode =
            RestoreExecutableMode(executable.clone(), fs::metadata(&executable)?.permissions());
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o500))?;
        let sha = format!("{:x}", Sha256::digest(fs::read(&executable)?));
        let config_path = root.join("config.toml");
        let config_text = |run_socket: &Path, run_executable: &Path, run_sha: &str| {
            format!(
                "socket_path = {:?}\ndatabase_path = {:?}\nexpected_uid = {}\nbridge_registration_socket = {:?}\nbridge_core_socket = {:?}\nbridge_credential_file = {:?}\nbridge_producer_id = 'pool'\nbridge_audience = 'pool'\nbridge_server_executable = {:?}\nbridge_server_sha256 = '{}'\n[managed_run_transport]\nsocket = {:?}\nexecutable = {:?}\nsha256 = '{}'\nrun_store_id = 'store_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'\nrun_route_id = 'run-route'\npool_route_id = 'pool-route'\nbridge_store_id = '00000000-0000-4000-8000-000000000003'\nbridge_route_id = 'bridge-route'\nproducer = 'pool'\n",
                root.join("pool.sock"),
                root.join("pool.db"),
                uid,
                bridge_socket,
                bridge_socket,
                credential,
                executable,
                sha,
                run_socket,
                run_executable,
                run_sha,
            )
        };
        fs::write(&config_path, config_text(&run_socket, &executable, &sha))?;
        let config = Config::load(&config_path)?;
        let mut initial = Store::open(&config.database_path)?;
        let pool_store = initial.managed_store_id()?;
        let peer = crate::managed_run::RunPeer::from_config(&config, &pool_store)
            .map_err(|_| "peer config")?;
        let (_, upgraded_bridge) =
            crate::managed_bridge::SdkBridge::capture(&config, peer.bridge_route.clone())?;
        let upgraded_run = peer.endpoint_pin();
        // The pre-upgrade pins name older versioned install paths and builds.
        let mut old_bridge = upgraded_bridge.clone();
        old_bridge.server_executable =
            "/opt/agent-bridge/releases/0.7.0+0123456789ab/bin/bridge-native-daemon".into();
        old_bridge.server_sha256 = "0".repeat(64);
        old_bridge.credential_sha256 = "1".repeat(64);
        let mut old_run = upgraded_run.clone();
        old_run.executable = "/opt/agent-run/releases/0.1.0/bin/agent-run".into();
        old_run.executable_sha256 = "2".repeat(64);
        initial.managed_pin_routes(&old_bridge, &old_run, &peer.pool_route)?;
        drop(initial);

        let bridge_task = tokio::spawn(async move {
            for _ in 0..3 {
                let (mut stream, _) = bridge_listener.accept().await?;
                let frame = integrations::read_frame(&mut stream).await?;
                let request: serde_json::Value = serde_json::from_slice(&frame)?;
                assert_eq!(request["op"], "attempt_binding_capabilities_v1");
                let response = serde_json::json!({"api_version":1,"request_id":request["request_id"],"success":true,"result":{"op":"attempt_binding_capabilities_v1","value":{"status":"ok","value":{"version":1,"store_id":"00000000-0000-4000-8000-000000000003","issuer_epoch":"epoch","capabilities":["attempt_launch_v1","launch_assertion_v1","namespace_retirement_v1"]}}}});
                stream.write_all(format!("{response}\n").as_bytes()).await?;
            }
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        });
        let run_task = tokio::spawn(async move {
            for index in 0..3 {
                let (mut stream, _) = run_listener.accept().await?;
                if index == 0 {
                    let mut byte = [0u8; 1];
                    assert_eq!(stream.read(&mut byte).await?, 0);
                    continue;
                }
                let frame = integrations::read_frame(&mut stream).await?;
                let request: serde_json::Value = serde_json::from_slice(&frame)?;
                assert_eq!(request["method"], "_attempt_capabilities_v1");
                let response = serde_json::json!({"id":request["id"],"result":{"version":1,"store_id":"store_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","capabilities":["attempt_current_ingress_v1","attempt_admission_v1"],"policy":"admission_snapshot"}});
                stream.write_all(format!("{response}\n").as_bytes()).await?;
            }
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        });
        let unchanged = || -> Result<(), Box<dyn std::error::Error>> {
            let mut store = Store::open(&config.database_path)?;
            assert_eq!(
                store.managed_repin_routes(&old_bridge, &old_run, &peer.pool_route, false)?,
                (1, 1)
            );
            assert_eq!(
                store.managed_repin_routes(
                    &upgraded_bridge,
                    &upgraded_run,
                    &peer.pool_route,
                    false
                )?,
                (1, 1)
            );
            Ok(())
        };
        // A moved socket is a route change: refused before any proof or I/O.
        fs::write(
            &config_path,
            config_text(&root.join("moved").join("attempt.sock"), &executable, &sha),
        )?;
        assert_eq!(repin(&config_path).await.err(), Some(Fault::Conflict));
        unchanged()?;
        // Untrusted candidates are refused before any peer I/O.
        fs::write(
            &config_path,
            config_text(&run_socket, &executable, &"3".repeat(64)),
        )?;
        assert_eq!(repin(&config_path).await.err(), Some(Fault::Unauthorized));
        let writable = root.join("run-writable");
        fs::write(&writable, "fixture-run-build")?;
        fs::set_permissions(&writable, fs::Permissions::from_mode(0o720))?;
        let writable_sha = format!("{:x}", Sha256::digest(fs::read(&writable)?));
        fs::write(
            &config_path,
            config_text(&run_socket, &writable, &writable_sha),
        )?;
        assert_eq!(repin(&config_path).await.err(), Some(Fault::Unauthorized));
        unchanged()?;
        // A trusted file that is not the live Run peer fails the live peer proof.
        let other = root.join("run-other");
        fs::write(&other, "fixture-run-build")?;
        fs::set_permissions(&other, fs::Permissions::from_mode(0o500))?;
        fs::write(
            &config_path,
            config_text(&run_socket, &other, &writable_sha),
        )?;
        assert_eq!(repin(&config_path).await.err(), Some(Fault::Unavailable));
        unchanged()?;
        fs::write(&config_path, config_text(&run_socket, &executable, &sha))?;
        assert_eq!(
            repin(&config_path)
                .await
                .map_err(|error| format!("verified candidate: {error}"))?,
            (2, 2)
        );
        assert_eq!(
            repin(&config_path)
                .await
                .map_err(|error| format!("replayed candidate: {error}"))?,
            (2, 2)
        );
        let mut repinned = Store::open(&config.database_path)?;
        assert_eq!(
            repinned.managed_repin_routes(
                &upgraded_bridge,
                &upgraded_run,
                &peer.pool_route,
                false
            )?,
            (2, 2)
        );
        repinned.managed_pin_routes(&upgraded_bridge, &upgraded_run, &peer.pool_route)?;
        drop(repinned);
        bridge_task.await?.map_err(|_| "Bridge fixture")?;
        run_task.await?.map_err(|_| "Run fixture")?;
        Ok(())
    }

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
            bridge_server_executable: "/fixture/bridge".into(),
            bridge_server_sha256: "0".repeat(64),
            bridge_observer_socket: None,
            bridge_observer_credential_file: None,
            owner_observer_credential_file: None,
            run_socket: Some(path.join("run.sock")),
            run_peer_uid: None,
            managed_run_reader: None,
            managed_run_transport: None,
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
            bridge_server_executable: "/fixture/bridge".into(),
            bridge_server_sha256: "0".repeat(64),
            bridge_observer_socket: None,
            bridge_observer_credential_file: None,
            owner_observer_credential_file: None,
            run_socket: Some(path.join("run.sock")),
            run_peer_uid: None,
            managed_run_reader: None,
            managed_run_transport: None,
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
            bridge_server_executable: "/fixture/bridge".into(),
            bridge_server_sha256: "0".repeat(64),
            bridge_observer_socket: None,
            bridge_observer_credential_file: None,
            owner_observer_credential_file: None,
            run_socket: Some(path.join("run.sock")),
            run_peer_uid: None,
            managed_run_reader: None,
            managed_run_transport: None,
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
            bridge_server_executable: "/fixture/bridge".into(),
            bridge_server_sha256: "0".repeat(64),
            bridge_observer_socket: None,
            bridge_observer_credential_file: None,
            owner_observer_credential_file: None,
            run_socket: Some(path.join("run.sock")),
            run_peer_uid: None,
            managed_run_reader: None,
            managed_run_transport: None,
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
            bridge_server_executable: "/fixture/bridge".into(),
            bridge_server_sha256: "0".repeat(64),
            bridge_observer_socket: None,
            bridge_observer_credential_file: None,
            owner_observer_credential_file: None,
            run_socket: Some(path.join("run.sock")),
            run_peer_uid: None,
            managed_run_reader: None,
            managed_run_transport: None,
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
            bridge_server_executable: "/fixture/bridge".into(),
            bridge_server_sha256: "0".repeat(64),
            bridge_observer_socket: None,
            bridge_observer_credential_file: None,
            owner_observer_credential_file: None,
            run_socket: Some(path.join("run.sock")),
            run_peer_uid: None,
            managed_run_reader: None,
            managed_run_transport: None,
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
            bridge_server_executable: "/fixture/bridge".into(),
            bridge_server_sha256: "0".repeat(64),
            bridge_observer_socket: None,
            bridge_observer_credential_file: None,
            owner_observer_credential_file: None,
            run_socket: Some(path.join("run.sock")),
            run_peer_uid: None,
            managed_run_reader: None,
            managed_run_transport: None,
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
            bridge_server_executable: "/fixture/bridge".into(),
            bridge_server_sha256: "0".repeat(64),
            bridge_observer_socket: None,
            bridge_observer_credential_file: None,
            owner_observer_credential_file: None,
            run_socket: Some(path.join("run.sock")),
            run_peer_uid: None,
            managed_run_reader: None,
            managed_run_transport: None,
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
            bridge_server_executable: "/fixture/bridge".into(),
            bridge_server_sha256: "0".repeat(64),
            bridge_observer_socket: None,
            bridge_observer_credential_file: None,
            owner_observer_credential_file: None,
            run_socket: Some(home.join("api.sock")),
            run_peer_uid: None,
            managed_run_reader: None,
            managed_run_transport: None,
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
            bridge_server_executable: "/fixture/bridge".into(),
            bridge_server_sha256: "0".repeat(64),
            bridge_observer_socket: None,
            bridge_observer_credential_file: None,
            owner_observer_credential_file: None,
            run_socket: Some(home.join("api.sock")),
            run_peer_uid: None,
            managed_run_reader: None,
            managed_run_transport: None,
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
        let (server, response) = tokio::time::timeout(Duration::from_secs(15), async {
            tokio::join!(
                connection(
                    server,
                    config.clone(),
                    Arc::clone(store),
                    Arc::new(ManagedActivity::default()),
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
            bridge_server_executable: "/fixture/bridge".into(),
            bridge_server_sha256: "0".repeat(64),
            bridge_observer_socket: None,
            bridge_observer_credential_file: None,
            owner_observer_credential_file: Some(token),
            run_socket: None,
            run_peer_uid: None,
            managed_run_reader: None,
            managed_run_transport: None,
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
            serde_json::json!({"schema_version":1,"operation":"inventory_snapshot","params":{"filter":"all","limit":10}}),
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

    /// A separately pinned Run reader can inspect outcomes and seal its exact namespace.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn managed_run_reader_is_build_and_namespace_fenced()
    -> Result<(), Box<dyn std::error::Error>> {
        use sha2::Digest;
        let _hash_guard = crate::TEST_EXEC_HASH_LOCK.lock().await;
        let directory =
            tempfile::tempdir_in(std::env::var_os("TMPDIR").ok_or("task TMPDIR required")?)?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let path = directory.path();
        let executable = std::env::current_exe()?;
        let sha256 = format!("{:x}", sha2::Sha256::digest(fs::read(&executable)?));
        let uid = fs::metadata(path)?.uid();
        let mut config = Config {
            socket_path: path.join("pool.sock"),
            database_path: path.join("pool.db"),
            expected_uid: uid,
            bridge_registration_socket: path.join("absent-registration.sock"),
            bridge_core_socket: path.join("absent-core.sock"),
            bridge_credential_file: path.join("absent-token"),
            bridge_producer_id: "pool".into(),
            bridge_audience: "pool".into(),
            bridge_server_executable: "/fixture/bridge".into(),
            bridge_server_sha256: "0".repeat(64),
            bridge_observer_socket: None,
            bridge_observer_credential_file: None,
            owner_observer_credential_file: None,
            run_socket: None,
            run_peer_uid: None,
            managed_run_reader: Some(crate::config::ManagedRunReader {
                executable,
                sha256,
                bridge_store_id: "00000000-0000-4000-8000-000000000001".into(),
                bridge_route_id: "bridge-route".into(),
                producer: "pool".into(),
                run_store_id: "store_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                run_route_id: "run-route".into(),
            }),
            managed_run_transport: None,
        };
        let initial = Store::open(&config.database_path)?;
        let store_id = initial.managed_store_id()?;
        let store = Arc::new(Mutex::new(initial));
        let request = serde_json::json!({"id":"outcome","method":"_managed_intent_outcome_v1","params":{"version":1,"expected_store_id":store_id,"intent_id":"missing","security_digest":"a".repeat(64)}});
        let result = observer_exchange(&config, &store, request.clone()).await?;
        assert_eq!(result["id"], "outcome");
        assert_eq!(result["result"]["state"], "absent");
        assert!(result["result"]["outcome_digest"].is_null());
        let seal = serde_json::json!({"id":"seal","method":"_managed_namespace_seal_v1","params":{"version":1,"expected_store_id":store_id,"request_id":"seal-request","bridge_route":{"component_store_id":"00000000-0000-4000-8000-000000000001","route_id":"bridge-route","worker_uid":uid},"producer":"pool","issuer_epoch":"old-epoch","retirement_key":"retire"}});
        let first = observer_exchange(&config, &store, seal.clone()).await?;
        assert_eq!(first["result"]["state"], "sealed");
        let again = observer_exchange(&config, &store, seal.clone()).await?;
        assert_eq!(first["result"]["seal_id"], again["result"]["seal_id"]);
        let mut foreign = seal;
        foreign["params"]["bridge_route"]["route_id"] = serde_json::json!("foreign-route");
        let denied_route = observer_exchange(&config, &store, foreign).await?;
        assert_eq!(denied_route["error"]["code"], "route_mismatch");
        config.managed_run_reader.as_mut().ok_or("reader")?.sha256 = "0".repeat(64);
        let denied = observer_exchange(&config, &store, request).await?;
        assert_eq!(denied["error"]["code"], "peer_not_authorized");
        Ok(())
    }

    /// A managed session authenticates both processes as the same loaded Pool build.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn managed_session_peer_requires_same_loaded_build()
    -> Result<(), Box<dyn std::error::Error>> {
        use tokio::io::AsyncReadExt;

        if let Some(socket) = std::env::var_os("POOL_MANAGED_PEER_FIXTURE") {
            let uid = std::fs::metadata(&socket)?.uid();
            let result = connect_managed_peer(Path::new(&socket), uid).await;
            if std::env::var_os("POOL_MANAGED_PEER_REJECT").is_some() {
                assert!(matches!(result, Err(Fault::Unauthorized)));
            } else {
                let mut stream = result?;
                stream.write_all(b"fixture").await?;
                let mut ack = [0];
                tokio::time::timeout(Duration::from_secs(60), stream.read_exact(&mut ack))
                    .await??;
                assert_eq!(ack, [1]);
            }
            return Ok(());
        }

        let _hash_guard = crate::TEST_EXEC_HASH_LOCK.lock().await;
        let directory =
            tempfile::tempdir_in(std::env::var_os("TMPDIR").ok_or("task TMPDIR required")?)?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let path = directory.path().join("peer.sock");
        let listener = UnixListener::bind(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let uid = fs::metadata(&path)?.uid();
        let original = std::env::current_exe()?;
        let other_path = directory.path().join("other-pool");
        fs::hard_link(&original, &other_path)?;
        for (executable, reject) in [(&original, false), (&other_path, true)] {
            let mut child = tokio::process::Command::new(executable)
                .args([
                    "--exact",
                    "runtime::tests::managed_session_peer_requires_same_loaded_build",
                ])
                .env_clear()
                .env("POOL_MANAGED_PEER_FIXTURE", &path)
                .envs(reject.then_some(("POOL_MANAGED_PEER_REJECT", "1")))
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .kill_on_drop(true)
                .spawn()?;
            let (mut stream, _) =
                tokio::time::timeout(Duration::from_secs(60), listener.accept()).await??;
            let authenticated = verify_managed_peer(&stream, uid).await;
            if reject {
                assert!(matches!(authenticated, Err(Fault::Unauthorized)));
                let mut byte = [0];
                assert_eq!(
                    tokio::time::timeout(Duration::from_secs(60), stream.read(&mut byte)).await??,
                    0
                );
            } else {
                authenticated?;
                let mut message = [0; 7];
                tokio::time::timeout(Duration::from_secs(60), stream.read_exact(&mut message))
                    .await??;
                assert_eq!(&message, b"fixture");
                stream.write_all(&[1]).await?;
            }
            assert!(
                tokio::time::timeout(Duration::from_secs(60), child.wait())
                    .await??
                    .success()
            );
        }
        Ok(())
    }

    /// The full private session connects fake Bridge and Run through real local CAS.
    #[tokio::test]
    async fn managed_stdio_session_runs_fresh_post_with_fake_bridge_and_run()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::managed_bridge::{BridgeB1Client, BridgeFailure};
        use crate::managed_session::{ClientFrame, ServerFrame};
        use crate::managed_state::tests::{
            FakeRun, fake_bridge_pin, fake_config, fake_consumed, fake_run_endpoint, fixture,
            index_managed_member, native_proof,
        };
        use std::sync::atomic::{AtomicUsize, Ordering};

        #[derive(Clone)]
        struct FakeServices {
            binding: crate::managed_state::ManagedBinding,
            incarnation: crate::managed_state::Incarnation,
            run: Arc<FakeRun>,
            calls: Arc<AtomicUsize>,
        }
        impl managed_dispatch::IngressClient for FakeServices {
            fn current<'a>(
                &'a self,
                query: &'a crate::managed_run::IngressQuery,
            ) -> managed_dispatch::Response<
                'a,
                crate::managed_run::CurrentAuthority,
                crate::managed_run::RunError,
            > {
                Box::pin(async move {
                    let index = self.calls.fetch_add(1, Ordering::SeqCst);
                    if index == 0 {
                        return Err(crate::managed_run::RunError::NotReady);
                    }
                    let mut receipt = self.run.receipt.clone();
                    receipt.receipt_id = format!("session-receipt-{index}");
                    query
                        .fixture_authority(receipt)
                        .map_err(|_| crate::managed_run::RunError::Unknown)
                })
            }
        }
        impl managed_dispatch::Client for FakeServices {
            fn admit<'a>(
                &'a self,
                plan: &'a crate::managed_state::AdmissionPlan,
            ) -> managed_dispatch::Response<
                'a,
                crate::managed_run::Admission,
                crate::managed_run::RunError,
            > {
                Box::pin(async move {
                    Ok(crate::managed_run::Admission {
                        admission_id: "session-admission".into(),
                        intent_id: plan.recovery.intent_id.clone(),
                        security_digest: plan.recovery.security_digest.clone(),
                        policy: "admission_snapshot".into(),
                        binding: plan.binding.clone(),
                        incarnation: self.incarnation.clone(),
                        successor_proof: self.run.receipt.successor_proof.clone(),
                        consumed_ref: plan.recovery.consumed_ref.clone(),
                    })
                })
            }
            fn consensus<'a>(
                &'a self,
                pending: crate::managed_state::PendingConsensus,
                _store: &'a SharedStore,
                _lease: &'a ManagedLease,
            ) -> managed_dispatch::Response<'a, crate::managed_state::ConsensusFence> {
                Box::pin(async move { pending.verify(self.run.as_ref()) })
            }
        }
        impl BridgeB1Client for FakeServices {
            fn capabilities(&self) -> Result<crate::managed_bridge::Capabilities, BridgeFailure> {
                Ok(crate::managed_bridge::Capabilities {
                    store_id: self.binding.bridge_route.component_store_id.clone(),
                    issuer_epoch: "epoch".into(),
                    capabilities: vec![
                        "attempt_launch_v1".into(),
                        "launch_assertion_v1".into(),
                        "namespace_retirement_v1".into(),
                    ],
                })
            }
            fn prepare(
                &self,
                request: &crate::managed_bridge::Prepare<'_>,
            ) -> Result<crate::managed_bridge::Prepared, BridgeFailure> {
                if request.command_name != "pool_post" || request.invocation_key != "session-inv" {
                    return Err(BridgeFailure::Refused);
                }
                Ok(crate::managed_bridge::Prepared {
                    store_id: self.binding.bridge_route.component_store_id.clone(),
                    bridge_context_ref: bridge_sdk::bridge_protocol::Secret::new("session-ref"),
                    invocation_key: request.invocation_key.into(),
                    expires_at_ms: 2,
                })
            }
            fn register(
                &self,
                request: &crate::managed_bridge::Registration<'_>,
            ) -> Result<crate::managed_bridge::Registered, BridgeFailure> {
                if request.bridge_context_ref != "session-ref"
                    || request.command_name != "pool_post"
                {
                    return Err(BridgeFailure::Refused);
                }
                Ok(crate::managed_bridge::Registered {
                    store_id: self.binding.bridge_route.component_store_id.clone(),
                    assertion_key: bridge_sdk::bridge_protocol::Secret::new("session-assertion"),
                    invocation_key: request.invocation_key.into(),
                    issuer_epoch: "epoch".into(),
                    expires_at_ms: 2,
                })
            }
            fn consume(
                &self,
                key: &crate::managed_bridge::ConsumeKey<'_>,
                assertion: &bridge_sdk::bridge_protocol::Secret,
            ) -> Result<crate::managed_bridge::Consumed, BridgeFailure> {
                if assertion.expose() != "session-assertion" {
                    return Err(BridgeFailure::Refused);
                }
                let command = Command::Post(crate::domain::Message {
                    change: crate::domain::Change {
                        pool_id: "pool".into(),
                        expected_revision: 1,
                        request_key: "session-key".into(),
                    },
                    body: "session post".into(),
                });
                Ok(fake_consumed(
                    &self.binding,
                    &self.incarnation,
                    key.consume_request_id,
                    key.invocation_key,
                    key.security_digest,
                    &command,
                ))
            }
            fn lookup(
                &self,
                _: &str,
                _: &crate::managed_bridge::ConsumeKey<'_>,
            ) -> Result<crate::managed_bridge::Consumed, BridgeFailure> {
                Err(BridgeFailure::Refused)
            }
            fn abort(
                &self,
                _: &crate::managed_bridge::ConsumeKey<'_>,
            ) -> Result<crate::managed_bridge::Abort, BridgeFailure> {
                Err(BridgeFailure::Refused)
            }
        }
        impl managed_dispatch::SessionClient for FakeServices {
            fn current_pin<'a>(
                &'a self,
            ) -> managed_dispatch::Response<'a, crate::managed_state::RunPin> {
                Box::pin(async move {
                    let endpoint = fake_run_endpoint(&self.binding);
                    Ok(crate::managed_state::RunPin {
                        route: endpoint.route,
                        socket: endpoint.socket,
                        executable: endpoint.executable,
                        executable_sha256: endpoint.executable_sha256,
                        capabilities: vec![
                            "attempt_current_ingress_v1".into(),
                            "attempt_admission_v1".into(),
                        ],
                    })
                })
            }
            fn endpoint(&self) -> crate::managed_state::RunEndpointPin {
                fake_run_endpoint(&self.binding)
            }
            fn pool_route(&self) -> crate::managed_state::Route {
                crate::managed_state::Route {
                    component_store_id: self.binding.pool_store_id.clone(),
                    route_id: "pool-route".into(),
                    worker_uid: self.binding.run_route.worker_uid,
                }
            }
            fn consume(
                &self,
                key: &crate::managed_bridge::ConsumeKey<'_>,
                assertion: &bridge_sdk::bridge_protocol::Secret,
                server: &str,
                command: &Command,
                epoch: &str,
            ) -> Result<crate::managed_bridge::Consumed, BridgeFailure> {
                crate::managed_bridge::consume_original(
                    self, key, assertion, server, command, epoch,
                )
            }
        }

        let (_directory, mut initial, binding, incarnation, run) = fixture();
        let db = initial.test_db();
        index_managed_member(db, &binding);
        let raw: String =
            db.query_row("SELECT data FROM members WHERE id='member'", [], |row| {
                row.get(0)
            })?;
        let mut member: Binding = serde_json::from_str(&raw)?;
        member.member.state = crate::domain::MemberState::Active;
        member.run_id = Some(binding.attempt.execution_id.clone());
        member.run_sequence = Some(u64::from(binding.attempt.sequence));
        db.execute(
            "UPDATE members SET data=?1 WHERE id='member'",
            [serde_json::to_string(&member)?],
        )?;
        let command = Command::Post(crate::domain::Message {
            change: crate::domain::Change {
                pool_id: "pool".into(),
                expected_revision: 1,
                request_key: "session-key".into(),
            },
            body: "session post".into(),
        });
        let normalized = serde_json::to_value(&command)?;
        let proof = native_proof();
        let pin = fake_bridge_pin(&binding);
        let services = FakeServices {
            binding: binding.clone(),
            incarnation,
            run: Arc::new(run),
            calls: Arc::new(AtomicUsize::new(0)),
        };
        let mut config = fake_config(&binding);
        let transport = config.managed_run_transport.as_mut().ok_or("transport")?;
        transport.frontend_enabled = true;
        transport.mcp_server = Some("pool".into());
        let begin = crate::managed_session::Begin {
            version: 1,
            bootstrap_id: "session-bootstrap".into(),
            invocation_key: "session-inv".into(),
            command: normalized.clone(),
            proof: proof.clone(),
            bridge_pin: pin.clone(),
        };
        let store = Arc::new(Mutex::new(initial));
        let activity = Arc::new(ManagedActivity::default());
        let lease = activity
            .acquire(ManagedWork::Bootstrap("session-bootstrap".into()))?
            .ok_or("lease")?;
        let (mut client, mut server) = UnixStream::pair()?;
        let task_store = Arc::clone(&store);
        let task_activity = Arc::clone(&activity);
        let task_config = config.clone();
        let task_services = services.clone();
        let task_command = command.clone();
        let task_normalized = normalized.clone();
        let task_pin = pin.clone();
        let task = tokio::spawn(async move {
            managed_session_core(
                &mut server,
                &task_config,
                &task_store,
                &task_activity,
                begin,
                task_command,
                task_normalized,
                task_pin,
                lease,
                task_services,
            )
            .await
        });
        assert!(matches!(
            crate::managed_session::receive::<ServerFrame>(&mut client).await?,
            ServerFrame::Ready
        ));
        let epoch = crate::managed_bridge::discover(&services, &pin.route.component_store_id)
            .map_err(|_| "fake discovery")?;
        crate::managed_session::send(
            &mut client,
            &ClientFrame::Epoch {
                issuer_epoch: epoch.clone(),
            },
        )
        .await?;
        assert!(matches!(
            crate::managed_session::receive::<ServerFrame>(&mut client).await?,
            ServerFrame::Reserved
        ));
        let prepared = services
            .prepare(&crate::managed_bridge::Prepare {
                request_id: "prepare",
                expected_store_id: &pin.route.component_store_id,
                expected_issuer_epoch: &epoch,
                invocation_key: "session-inv",
                command_name: "pool_post",
                native_proof: &proof,
            })
            .map_err(|_| "fake prepare")?;
        crate::managed_session::send(
            &mut client,
            &ClientFrame::Prepared {
                store_id: prepared.store_id.clone(),
                bridge_context_ref: prepared.bridge_context_ref.clone(),
                invocation_key: prepared.invocation_key.clone(),
                expires_at_ms: prepared.expires_at_ms,
            },
        )
        .await?;
        let ServerFrame::Context(frozen) =
            crate::managed_session::receive::<ServerFrame>(&mut client).await?
        else {
            return Err("missing frozen context".into());
        };
        let (_, digest) = crate::managed_codec::security_digest(
            &normalized,
            &serde_json::to_value(&frozen.context)?,
        )?;
        assert_eq!(digest, frozen.security_digest);
        let registration = crate::managed_bridge::Registration {
            request_id: &frozen.registration_request_id,
            expected_store_id: &prepared.store_id,
            bridge_context_ref: prepared.bridge_context_ref.expose(),
            invocation_key: &prepared.invocation_key,
            command_name: "pool_post",
            security_digest: &digest,
            audience: "pool",
            nonce: &frozen.context.nonce,
            native_proof: &proof,
        };
        let registered = crate::managed_bridge::register_original(
            &services,
            &registration,
            &prepared,
            &epoch,
            &command,
        )
        .map_err(|_| "fake register")?;
        crate::managed_session::send(
            &mut client,
            &ClientFrame::Execute {
                assertion_key: registered.assertion_key,
            },
        )
        .await?;
        let ServerFrame::Finished(Ok(Reply::Receipt(receipt))) =
            crate::managed_session::receive::<ServerFrame>(&mut client).await?
        else {
            return Err("missing committed receipt".into());
        };
        assert_eq!(receipt.event.body, "session post");
        assert_eq!(receipt.revision, 2);
        task.await??;
        assert_eq!(services.calls.load(Ordering::SeqCst), 3);
        let state = stored(&store, |store| {
            Ok(store
                .test_db()
                .query_row("SELECT state FROM managed_intents", [], |row| {
                    row.get::<_, String>(0)
                })?)
        })
        .await?;
        assert_eq!(state, "committed");
        Ok(())
    }

    /// E12: a publish killed before reaching Bridge resolves by bounded exact
    /// lookups, then exact abort, then exactly one NEW effect for the same
    /// event that is delivered once; a publish Bridge already accepted resolves
    /// by lookup with no abort or republish.
    #[tokio::test]
    async fn e12_unknown_publish_aborts_then_republishes_once()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::managed_egress::tests::{add_seed, freeze_next, result};
        use crate::managed_egress::{Frozen, OwnerClient, OwnerFailure, ScopePlan, State};
        use crate::managed_state::tests::{fixture, index_managed_member};
        use bridge_sdk::bridge_protocol::{
            RetireResult,
            managed_owner::{
                CompactManagedOwnerScopeResultV1, ManagedOwnerResultV1, ManagedOwnerStateV1,
            },
        };
        #[derive(Clone, Default)]
        struct Owner {
            calls: Arc<Mutex<Vec<(String, String)>>>,
        }
        impl Owner {
            fn log(&self, kind: &str, frozen: &Frozen) -> Result<(), OwnerFailure> {
                self.calls
                    .lock()
                    .map_err(|_| OwnerFailure::Unknown)?
                    .push((kind.into(), frozen.seed.effect_id.clone()));
                Ok(())
            }
            fn count(&self, kind: &str) -> usize {
                self.calls
                    .lock()
                    .map(|calls| calls.iter().filter(|(k, _)| k == kind).count())
                    .unwrap_or(usize::MAX)
            }
        }
        impl OwnerClient for Owner {
            fn capabilities(&self, _: &str) -> Result<(), OwnerFailure> {
                Ok(())
            }
            fn publish(
                &self,
                _: &str,
                frozen: &Frozen,
            ) -> Result<ManagedOwnerResultV1, OwnerFailure> {
                self.log("publish", frozen)?;
                Ok(result(frozen, ManagedOwnerStateV1::Accepted, None))
            }
            fn lookup(
                &self,
                _: &str,
                frozen: &Frozen,
            ) -> Result<ManagedOwnerResultV1, OwnerFailure> {
                self.log("lookup", frozen)?;
                if frozen.seed.effect_id == "e12-accepted" {
                    Ok(result(frozen, ManagedOwnerStateV1::Accepted, None))
                } else {
                    // Missing Bridge custody: binding_unavailable/same_key_lookup.
                    Err(OwnerFailure::Unknown)
                }
            }
            fn abort(
                &self,
                _: &str,
                frozen: &Frozen,
            ) -> Result<ManagedOwnerResultV1, OwnerFailure> {
                self.log("abort", frozen)?;
                if self.count("abort") == 1 {
                    return Err(OwnerFailure::Unknown);
                }
                Ok(result(frozen, ManagedOwnerStateV1::Aborted, None))
            }
            fn retire(&self, _: &str, _: &ScopePlan) -> Result<RetireResult, OwnerFailure> {
                Err(OwnerFailure::Unknown)
            }
            fn compact(
                &self,
                _: &str,
                _: &ScopePlan,
            ) -> Result<CompactManagedOwnerScopeResultV1, OwnerFailure> {
                Err(OwnerFailure::Unknown)
            }
        }
        let (dir, mut initial, binding, incarnation, _run) = fixture();
        index_managed_member(initial.test_db(), &binding);
        let event = add_seed(&mut initial, &binding, "e12-lost", "payload", false);
        add_seed(&mut initial, &binding, "e12-accepted", "accepted", false);
        let lost = freeze_next(&mut initial, &binding, &incarnation, "e12-lost", "next", 2);
        let rebound: crate::managed_state::ManagedBinding =
            serde_json::from_str(&initial.test_db().query_row(
                "SELECT binding FROM managed_bindings WHERE member='member'",
                [],
                |row| row.get::<_, String>(0),
            )?)?;
        let accepted = freeze_next(
            &mut initial,
            &rebound,
            &incarnation,
            "e12-accepted",
            "third",
            3,
        );
        // Both publishes are claimed, then the resident is killed before any
        // byte reached Bridge (lost) or after Bridge accepted (accepted).
        initial.egress_begin_publish("e12-lost")?;
        initial.egress_begin_publish("e12-accepted")?;
        drop(initial);
        let reopened = Store::open(&dir.path().join("pool.db"))?;
        let store = Arc::new(Mutex::new(reopened));
        assert_eq!(
            stored(&store, |store| store.egress_state("e12-lost")).await?,
            Some(State::Unknown)
        );
        let owner = Owner::default();
        let activity = Arc::new(ManagedActivity::default());
        // Accepted after kill: exact lookup resolves delivered; no abort/republish.
        let lease = activity
            .acquire(ManagedWork::Egress("e12-accepted".into()))?
            .ok_or("lease")?;
        managed_egress_dispatch::liveness(
            &store,
            &lease,
            accepted,
            owner.clone(),
            State::Unknown,
            100,
        )
        .await?;
        drop(lease);
        assert_eq!(
            stored(&store, |store| store.egress_state("e12-accepted")).await?,
            Some(State::Accepted)
        );
        assert_eq!((owner.count("abort"), owner.count("publish")), (0, 0));
        // Lost before Bridge: bounded lookups with backoff, never a resend.
        let lease = activity
            .acquire(ManagedWork::Egress("e12-lost".into()))?
            .ok_or("lease")?;
        for (now, lookups) in [(100, 2), (101, 2), (105, 3), (114, 3), (115, 4)] {
            let state = stored(&store, |store| store.egress_state("e12-lost"))
                .await?
                .ok_or("state")?;
            managed_egress_dispatch::liveness(
                &store,
                &lease,
                lost.clone(),
                owner.clone(),
                state,
                now,
            )
            .await?;
            assert_eq!(owner.count("lookup"), lookups, "at {now}");
        }
        assert_eq!(
            stored(&store, |store| store.egress_state("e12-lost")).await?,
            Some(State::AbortPending)
        );
        assert_eq!(owner.count("publish"), 0);
        // Abort transport loss stays fenced with attention, retried after backoff.
        managed_egress_dispatch::liveness(
            &store,
            &lease,
            lost.clone(),
            owner.clone(),
            State::AbortPending,
            135,
        )
        .await?;
        assert_eq!(owner.count("abort"), 1);
        assert_eq!(
            stored(&store, |store| store.egress_state("e12-lost")).await?,
            Some(State::AbortPending)
        );
        let attention = stored(&store, |store| {
            crate::managed_egress::owner_attention(store.test_db(), "e12-lost")
        })
        .await?;
        assert_eq!(attention.0.as_deref(), Some("outcome_unknown"));
        managed_egress_dispatch::liveness(
            &store,
            &lease,
            lost.clone(),
            owner.clone(),
            State::AbortPending,
            1000,
        )
        .await?;
        assert_eq!(
            stored(&store, |store| store.egress_state("e12-lost")).await?,
            Some(State::Aborted)
        );
        drop(lease);
        // Exactly one NEW effect for the same event; the original is never retargeted.
        let (fresh, live, event_key) = stored(&store, |store| {
            let db = store.test_db();
            let fresh: String = db.query_row(
                "SELECT republished_as FROM managed_delivery_liveness WHERE effect_id='e12-lost'",
                [],
                |row| row.get(0),
            )?;
            let live: i64 = db.query_row(
                "SELECT count(*) FROM managed_delivery_seeds s JOIN managed_delivery_outbox o ON o.effect_id=s.effect_id WHERE s.event_key=(SELECT event_key FROM managed_delivery_seeds WHERE effect_id='e12-lost') AND o.state NOT IN ('aborted','accepted','not_delivered')",
                [],
                |row| row.get(0),
            )?;
            let key: String = db.query_row(
                "SELECT event_key FROM managed_delivery_seeds WHERE effect_id=?1",
                [&fresh],
                |row| row.get(0),
            )?;
            Ok((fresh, live, key))
        })
        .await?;
        assert_ne!(fresh, "e12-lost");
        assert_eq!(live, 1);
        assert_eq!(event_key, format!("event/{event}"));
        let replay = fresh.clone();
        assert_eq!(
            stored(&store, move |store| store.egress_republish("e12-lost")).await?,
            Some(replay)
        );
        // The new effect follows the normal freeze rules and is delivered once.
        let current: crate::managed_state::ManagedBinding = serde_json::from_str(
            &stored(&store, |store| {
                Ok(store.test_db().query_row(
                    "SELECT binding FROM managed_bindings WHERE member='member'",
                    [],
                    |row| row.get::<_, String>(0),
                )?)
            })
            .await?,
        )?;
        let fresh_frozen = {
            let mut guard = store.lock().map_err(|_| "store")?;
            freeze_next(&mut guard, &current, &incarnation, &fresh, "fourth", 4)
        };
        assert_eq!(fresh_frozen.seed.event_key, lost.seed.event_key);
        assert_ne!(fresh_frozen.digest, lost.digest);
        let lease = activity
            .acquire(ManagedWork::Egress(fresh.clone()))?
            .ok_or("lease")?;
        managed_egress_dispatch::publish(&store, &lease, fresh_frozen, owner.clone()).await?;
        let state_id = fresh.clone();
        assert_eq!(
            stored(&store, move |store| store.egress_state(&state_id)).await?,
            Some(State::Accepted)
        );
        assert_eq!(owner.count("publish"), 1);
        assert!(
            owner
                .calls
                .lock()
                .map_err(|_| "calls")?
                .iter()
                .all(|(kind, id)| kind != "publish" || *id == fresh)
        );
        Ok(())
    }

    /// E12 failure boundaries: the durable `aborted` and its ONE successor
    /// commit together. A successor refused for capacity rolls the abort result
    /// back (the original stays fenced, no successor); after a restart and
    /// capacity recovery the same-key abort creates exactly one successor, and a
    /// replayed abort result after another restart creates none.
    #[tokio::test]
    async fn e12_abort_result_and_successor_commit_atomically()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::managed_egress::tests::{add_seed, freeze_next, result};
        use crate::managed_egress::{Frozen, OwnerClient, OwnerFailure, ScopePlan, State};
        use crate::managed_state::tests::{fixture, index_managed_member};
        use bridge_sdk::bridge_protocol::{
            RetireResult,
            managed_owner::{
                CompactManagedOwnerScopeResultV1, ManagedOwnerResultV1, ManagedOwnerStateV1,
            },
        };
        use std::sync::atomic::{AtomicUsize, Ordering};
        #[derive(Clone, Default)]
        struct Owner {
            aborts: Arc<AtomicUsize>,
        }
        impl OwnerClient for Owner {
            fn capabilities(&self, _: &str) -> Result<(), OwnerFailure> {
                Ok(())
            }
            fn publish(&self, _: &str, _: &Frozen) -> Result<ManagedOwnerResultV1, OwnerFailure> {
                Err(OwnerFailure::Unknown)
            }
            fn lookup(&self, _: &str, _: &Frozen) -> Result<ManagedOwnerResultV1, OwnerFailure> {
                Err(OwnerFailure::Unknown)
            }
            fn abort(
                &self,
                _: &str,
                frozen: &Frozen,
            ) -> Result<ManagedOwnerResultV1, OwnerFailure> {
                self.aborts.fetch_add(1, Ordering::SeqCst);
                Ok(result(frozen, ManagedOwnerStateV1::Aborted, None))
            }
            fn retire(&self, _: &str, _: &ScopePlan) -> Result<RetireResult, OwnerFailure> {
                Err(OwnerFailure::Unknown)
            }
            fn compact(
                &self,
                _: &str,
                _: &ScopePlan,
            ) -> Result<CompactManagedOwnerScopeResultV1, OwnerFailure> {
                Err(OwnerFailure::Unknown)
            }
        }
        /// (successor links, live effects for the event, original effect row state).
        fn census(store: &mut Store) -> Result<(i64, i64, String), Fault> {
            let db = store.test_db();
            Ok((
                db.query_row(
                    "SELECT count(*) FROM managed_delivery_liveness WHERE effect_id='e12-cap' AND republished_as IS NOT NULL",
                    [],
                    |row| row.get(0),
                )?,
                db.query_row(
                    "SELECT count(*) FROM managed_delivery_seeds s JOIN managed_delivery_outbox o ON o.effect_id=s.effect_id WHERE s.event_key=(SELECT event_key FROM managed_delivery_seeds WHERE effect_id='e12-cap') AND o.state NOT IN ('aborted','accepted','not_delivered')",
                    [],
                    |row| row.get(0),
                )?,
                db.query_row("SELECT state FROM effects WHERE id='e12-cap'", [], |row| {
                    row.get(0)
                })?,
            ))
        }
        let (dir, mut initial, binding, incarnation, _run) = fixture();
        index_managed_member(initial.test_db(), &binding);
        add_seed(&mut initial, &binding, "e12-cap", "payload", false);
        let lost = freeze_next(&mut initial, &binding, &incarnation, "e12-cap", "next", 2);
        initial.egress_begin_publish("e12-cap")?;
        drop(initial);
        let path = dir.path().join("pool.db");
        let store = Arc::new(Mutex::new(Store::open(&path)?));
        let owner = Owner::default();
        let activity = Arc::new(ManagedActivity::default());
        let lease = activity
            .acquire(ManagedWork::Egress("e12-cap".into()))?
            .ok_or("lease")?;
        for now in [100, 105, 115] {
            let state = stored(&store, |store| store.egress_state("e12-cap"))
                .await?
                .ok_or("state")?;
            managed_egress_dispatch::liveness(
                &store,
                &lease,
                lost.clone(),
                owner.clone(),
                state,
                now,
            )
            .await?;
        }
        assert_eq!(
            stored(&store, |store| store.egress_state("e12-cap")).await?,
            Some(State::AbortPending)
        );
        // Capacity exhausted: Bridge aborts, but the successor cannot be
        // inserted, so the abort result is not committed either.
        stored(&store, |store| {
            let db = store.test_db();
            db.execute_batch("PRAGMA foreign_keys=OFF; WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<100000) INSERT INTO managed_delivery_outbox(effect_id,state) SELECT 'filler-'||i,'pending' FROM n; PRAGMA foreign_keys=ON;")?;
            Ok(())
        })
        .await?;
        managed_egress_dispatch::liveness(
            &store,
            &lease,
            lost.clone(),
            owner.clone(),
            State::AbortPending,
            135,
        )
        .await?;
        assert_eq!(owner.aborts.load(Ordering::SeqCst), 1);
        assert_eq!(
            stored(&store, |store| store.egress_state("e12-cap")).await?,
            Some(State::AbortPending)
        );
        assert_eq!(
            stored(&store, census).await?,
            (0, 1, "unknown".into()),
            "no committed abort without its successor"
        );
        // Restart, then capacity recovers: the same-key abort is retried after
        // backoff and the result commits with exactly one successor.
        drop(lease);
        drop(store);
        let store = Arc::new(Mutex::new(Store::open(&path)?));
        stored(&store, |store| {
            store.test_db().execute(
                "DELETE FROM managed_delivery_outbox WHERE effect_id LIKE 'filler-%'",
                [],
            )?;
            Ok(())
        })
        .await?;
        let lease = activity
            .acquire(ManagedWork::Egress("e12-cap".into()))?
            .ok_or("lease")?;
        managed_egress_dispatch::liveness(
            &store,
            &lease,
            lost.clone(),
            owner.clone(),
            State::AbortPending,
            136,
        )
        .await?;
        assert_eq!(owner.aborts.load(Ordering::SeqCst), 1, "backoff respected");
        managed_egress_dispatch::liveness(
            &store,
            &lease,
            lost.clone(),
            owner.clone(),
            State::AbortPending,
            1000,
        )
        .await?;
        assert_eq!(owner.aborts.load(Ordering::SeqCst), 2);
        assert_eq!(
            stored(&store, |store| store.egress_state("e12-cap")).await?,
            Some(State::Aborted)
        );
        assert_eq!(stored(&store, census).await?, (1, 1, "cancelled".into()));
        let fresh = stored(&store, |store| {
            Ok(store.test_db().query_row(
                "SELECT republished_as FROM managed_delivery_liveness WHERE effect_id='e12-cap'",
                [],
                |row| row.get::<_, String>(0),
            )?)
        })
        .await?;
        // Restart after the committed abort result: a replayed abort result and
        // a replayed republish are idempotent and never mint a second successor.
        drop(lease);
        drop(store);
        let store = Arc::new(Mutex::new(Store::open(&path)?));
        let aborted = result(&lost, ManagedOwnerStateV1::Aborted, None);
        assert_eq!(
            stored(&store, move |store| store
                .egress_result("e12-cap", None, &aborted, true))
            .await?,
            State::Aborted
        );
        let replay = fresh.clone();
        assert_eq!(
            stored(&store, |store| store.egress_republish("e12-cap")).await?,
            Some(replay)
        );
        assert_eq!(stored(&store, census).await?, (1, 1, "cancelled".into()));
        let seeds = stored(&store, |store| {
            Ok(store.test_db().query_row(
                "SELECT count(*) FROM managed_delivery_seeds WHERE event_key=(SELECT event_key FROM managed_delivery_seeds WHERE effect_id='e12-cap')",
                [],
                |row| row.get::<_, i64>(0),
            )?)
        })
        .await?;
        assert_eq!(seeds, 2, "the original and exactly one successor");
        Ok(())
    }

    /// P3: an owner-enrolled, generation-1 bound member joins through the full
    /// managed frontend session (fake Bridge and Run endpoints, real local CAS).
    #[tokio::test]
    async fn p3_single_enrollment_session_join() -> Result<(), Box<dyn std::error::Error>> {
        use crate::managed_bridge::{BridgeB1Client, BridgeFailure};
        use crate::managed_session::{ClientFrame, ServerFrame};
        use crate::managed_state::tests::{
            fake_bridge_pin, fake_config, fake_consumed, fake_run_endpoint, native_proof,
        };

        #[derive(Clone)]
        struct Services {
            binding: crate::managed_state::ManagedBinding,
            incarnation: crate::managed_state::Incarnation,
            receipt: crate::managed_state::CurrentReceipt,
            command: Command,
        }
        impl managed_dispatch::IngressClient for Services {
            fn current<'a>(
                &'a self,
                query: &'a crate::managed_run::IngressQuery,
            ) -> managed_dispatch::Response<
                'a,
                crate::managed_run::CurrentAuthority,
                crate::managed_run::RunError,
            > {
                Box::pin(async move {
                    let mut receipt = self.receipt.clone();
                    receipt.receipt_id = format!("session-{}", crate::domain::id());
                    query
                        .fixture_authority(receipt)
                        .map_err(|_| crate::managed_run::RunError::Unknown)
                })
            }
        }
        impl managed_dispatch::Client for Services {
            fn admit<'a>(
                &'a self,
                plan: &'a crate::managed_state::AdmissionPlan,
            ) -> managed_dispatch::Response<
                'a,
                crate::managed_run::Admission,
                crate::managed_run::RunError,
            > {
                Box::pin(async move {
                    Ok(crate::managed_run::Admission {
                        admission_id: "session-join-admission".into(),
                        intent_id: plan.recovery.intent_id.clone(),
                        security_digest: plan.recovery.security_digest.clone(),
                        policy: "admission_snapshot".into(),
                        binding: plan.binding.clone(),
                        incarnation: self.incarnation.clone(),
                        successor_proof: self.receipt.successor_proof.clone(),
                        consumed_ref: plan.recovery.consumed_ref.clone(),
                    })
                })
            }
            fn consensus<'a>(
                &'a self,
                _: crate::managed_state::PendingConsensus,
                _: &'a SharedStore,
                _: &'a ManagedLease,
            ) -> managed_dispatch::Response<'a, crate::managed_state::ConsensusFence> {
                Box::pin(async move { Err(Fault::Unavailable) })
            }
        }
        impl BridgeB1Client for Services {
            fn capabilities(&self) -> Result<crate::managed_bridge::Capabilities, BridgeFailure> {
                Ok(crate::managed_bridge::Capabilities {
                    store_id: self.binding.bridge_route.component_store_id.clone(),
                    issuer_epoch: "epoch".into(),
                    capabilities: vec![
                        "attempt_launch_v1".into(),
                        "launch_assertion_v1".into(),
                        "namespace_retirement_v1".into(),
                    ],
                })
            }
            fn prepare(
                &self,
                request: &crate::managed_bridge::Prepare<'_>,
            ) -> Result<crate::managed_bridge::Prepared, BridgeFailure> {
                if request.command_name != "pool_join" {
                    return Err(BridgeFailure::Refused);
                }
                Ok(crate::managed_bridge::Prepared {
                    store_id: self.binding.bridge_route.component_store_id.clone(),
                    bridge_context_ref: bridge_sdk::bridge_protocol::Secret::new("join-ref"),
                    invocation_key: request.invocation_key.into(),
                    expires_at_ms: 2,
                })
            }
            fn register(
                &self,
                request: &crate::managed_bridge::Registration<'_>,
            ) -> Result<crate::managed_bridge::Registered, BridgeFailure> {
                if request.command_name != "pool_join" {
                    return Err(BridgeFailure::Refused);
                }
                Ok(crate::managed_bridge::Registered {
                    store_id: self.binding.bridge_route.component_store_id.clone(),
                    assertion_key: bridge_sdk::bridge_protocol::Secret::new("join-assertion"),
                    invocation_key: request.invocation_key.into(),
                    issuer_epoch: "epoch".into(),
                    expires_at_ms: 2,
                })
            }
            fn consume(
                &self,
                key: &crate::managed_bridge::ConsumeKey<'_>,
                assertion: &bridge_sdk::bridge_protocol::Secret,
            ) -> Result<crate::managed_bridge::Consumed, BridgeFailure> {
                if assertion.expose() != "join-assertion" {
                    return Err(BridgeFailure::Refused);
                }
                Ok(fake_consumed(
                    &self.binding,
                    &self.incarnation,
                    key.consume_request_id,
                    key.invocation_key,
                    key.security_digest,
                    &self.command,
                ))
            }
            fn lookup(
                &self,
                _: &str,
                _: &crate::managed_bridge::ConsumeKey<'_>,
            ) -> Result<crate::managed_bridge::Consumed, BridgeFailure> {
                Err(BridgeFailure::Refused)
            }
            fn abort(
                &self,
                _: &crate::managed_bridge::ConsumeKey<'_>,
            ) -> Result<crate::managed_bridge::Abort, BridgeFailure> {
                Err(BridgeFailure::Refused)
            }
        }
        impl managed_dispatch::SessionClient for Services {
            fn current_pin<'a>(
                &'a self,
            ) -> managed_dispatch::Response<'a, crate::managed_state::RunPin> {
                Box::pin(async move {
                    let endpoint = fake_run_endpoint(&self.binding);
                    Ok(crate::managed_state::RunPin {
                        route: endpoint.route,
                        socket: endpoint.socket,
                        executable: endpoint.executable,
                        executable_sha256: endpoint.executable_sha256,
                        capabilities: vec![
                            "attempt_current_ingress_v1".into(),
                            "attempt_admission_v1".into(),
                        ],
                    })
                })
            }
            fn endpoint(&self) -> crate::managed_state::RunEndpointPin {
                fake_run_endpoint(&self.binding)
            }
            fn pool_route(&self) -> crate::managed_state::Route {
                crate::managed_state::Route {
                    component_store_id: self.binding.pool_store_id.clone(),
                    route_id: "pool-route".into(),
                    worker_uid: self.binding.run_route.worker_uid,
                }
            }
            fn consume(
                &self,
                key: &crate::managed_bridge::ConsumeKey<'_>,
                assertion: &bridge_sdk::bridge_protocol::Secret,
                server: &str,
                command: &Command,
                epoch: &str,
            ) -> Result<crate::managed_bridge::Consumed, BridgeFailure> {
                crate::managed_bridge::consume_original(
                    self, key, assertion, server, command, epoch,
                )
            }
        }

        let mut harness = crate::enrollment_tests::Harness::new();
        let (enrollment, member) = harness.bound_member("session").await;
        let (binding, incarnation) = harness.managed_binding(&member).ok_or("binding")?;
        let mut receipt = harness.ingress_for(&member, "session");
        receipt.purpose = "ingress".into();
        let revision = harness.revision();
        let command = Command::Join(crate::domain::Change {
            pool_id: harness.pool.clone(),
            expected_revision: revision,
            request_key: "session-join".into(),
        });
        let normalized = serde_json::to_value(&command)?;
        let proof = native_proof();
        let pin = fake_bridge_pin(&binding);
        let services = Services {
            binding: binding.clone(),
            incarnation,
            receipt,
            command: command.clone(),
        };
        let mut config = fake_config(&binding);
        let transport = config.managed_run_transport.as_mut().ok_or("transport")?;
        transport.frontend_enabled = true;
        transport.mcp_server = Some("pool".into());
        let begin = crate::managed_session::Begin {
            version: 1,
            bootstrap_id: "join-bootstrap".into(),
            invocation_key: "join-inv".into(),
            command: normalized.clone(),
            proof: proof.clone(),
            bridge_pin: pin.clone(),
        };
        let store = Arc::clone(&harness.store);
        let activity = Arc::new(ManagedActivity::default());
        let lease = activity
            .acquire(ManagedWork::Bootstrap("join-bootstrap".into()))?
            .ok_or("lease")?;
        let (mut client, mut server) = UnixStream::pair()?;
        let task_store = Arc::clone(&store);
        let task_activity = Arc::clone(&activity);
        let task_services = services.clone();
        let task_command = command.clone();
        let task_normalized = normalized.clone();
        let task_pin = pin.clone();
        let task = tokio::spawn(async move {
            managed_session_core(
                &mut server,
                &config,
                &task_store,
                &task_activity,
                begin,
                task_command,
                task_normalized,
                task_pin,
                lease,
                task_services,
            )
            .await
        });
        assert!(matches!(
            crate::managed_session::receive::<ServerFrame>(&mut client).await?,
            ServerFrame::Ready
        ));
        let epoch = crate::managed_bridge::discover(&services, &pin.route.component_store_id)
            .map_err(|_| "fake discovery")?;
        crate::managed_session::send(
            &mut client,
            &ClientFrame::Epoch {
                issuer_epoch: epoch.clone(),
            },
        )
        .await?;
        assert!(matches!(
            crate::managed_session::receive::<ServerFrame>(&mut client).await?,
            ServerFrame::Reserved
        ));
        let prepared = services
            .prepare(&crate::managed_bridge::Prepare {
                request_id: "prepare",
                expected_store_id: &pin.route.component_store_id,
                expected_issuer_epoch: &epoch,
                invocation_key: "join-inv",
                command_name: "pool_join",
                native_proof: &proof,
            })
            .map_err(|_| "fake prepare")?;
        crate::managed_session::send(
            &mut client,
            &ClientFrame::Prepared {
                store_id: prepared.store_id.clone(),
                bridge_context_ref: prepared.bridge_context_ref.clone(),
                invocation_key: prepared.invocation_key.clone(),
                expires_at_ms: prepared.expires_at_ms,
            },
        )
        .await?;
        let ServerFrame::Context(frozen) =
            crate::managed_session::receive::<ServerFrame>(&mut client).await?
        else {
            return Err("missing frozen context".into());
        };
        assert_eq!(frozen.context.bindings, vec![binding.clone()]);
        let registration = crate::managed_bridge::Registration {
            request_id: &frozen.registration_request_id,
            expected_store_id: &prepared.store_id,
            bridge_context_ref: prepared.bridge_context_ref.expose(),
            invocation_key: &prepared.invocation_key,
            command_name: "pool_join",
            security_digest: &frozen.security_digest,
            audience: "pool",
            nonce: &frozen.context.nonce,
            native_proof: &proof,
        };
        let registered = crate::managed_bridge::register_original(
            &services,
            &registration,
            &prepared,
            &epoch,
            &command,
        )
        .map_err(|_| "fake register")?;
        crate::managed_session::send(
            &mut client,
            &ClientFrame::Execute {
                assertion_key: registered.assertion_key,
            },
        )
        .await?;
        let ServerFrame::Finished(Ok(Reply::Receipt(receipt))) =
            crate::managed_session::receive::<ServerFrame>(&mut client).await?
        else {
            return Err("missing committed join receipt".into());
        };
        assert_eq!(receipt.event.kind, "member_joined");
        task.await??;
        assert_eq!(
            harness.member(&member).0.member.state,
            crate::domain::MemberState::Active
        );
        assert_eq!(harness.view(&enrollment).jobs[0].state, "active");
        Ok(())
    }

    /// An unqualified Run launch cannot reach any managed participant operation.
    #[tokio::test]
    async fn unqualified_launch_blocks_all_managed_participant_commands()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::managed_state::tests::{
            fake_bridge_pin, fake_config, fake_run_endpoint, fixture, native_proof,
        };
        use std::sync::atomic::{AtomicUsize, Ordering};
        #[derive(Clone)]
        struct Refusing {
            binding: crate::managed_state::ManagedBinding,
            checks: Arc<AtomicUsize>,
            later: Arc<AtomicUsize>,
        }
        impl managed_dispatch::IngressClient for Refusing {
            fn current<'a>(
                &'a self,
                _: &'a crate::managed_run::IngressQuery,
            ) -> managed_dispatch::Response<
                'a,
                crate::managed_run::CurrentAuthority,
                crate::managed_run::RunError,
            > {
                Box::pin(async move {
                    if self.checks.fetch_add(1, Ordering::SeqCst) == 0 {
                        Err(crate::managed_run::RunError::NotReady)
                    } else {
                        Err(crate::managed_run::RunError::Refused)
                    }
                })
            }
        }
        impl managed_dispatch::Client for Refusing {
            fn admit<'a>(
                &'a self,
                _: &'a crate::managed_state::AdmissionPlan,
            ) -> managed_dispatch::Response<
                'a,
                crate::managed_run::Admission,
                crate::managed_run::RunError,
            > {
                Box::pin(async move {
                    self.later.fetch_add(1, Ordering::SeqCst);
                    Err(crate::managed_run::RunError::Refused)
                })
            }
            fn consensus<'a>(
                &'a self,
                _: crate::managed_state::PendingConsensus,
                _: &'a SharedStore,
                _: &'a ManagedLease,
            ) -> managed_dispatch::Response<'a, crate::managed_state::ConsensusFence> {
                Box::pin(async move {
                    self.later.fetch_add(1, Ordering::SeqCst);
                    Err(Fault::Unavailable)
                })
            }
        }
        impl managed_dispatch::SessionClient for Refusing {
            fn current_pin<'a>(
                &'a self,
            ) -> managed_dispatch::Response<'a, crate::managed_state::RunPin> {
                Box::pin(async move {
                    let endpoint = fake_run_endpoint(&self.binding);
                    Ok(crate::managed_state::RunPin {
                        route: endpoint.route,
                        socket: endpoint.socket,
                        executable: endpoint.executable,
                        executable_sha256: endpoint.executable_sha256,
                        capabilities: vec![
                            "attempt_current_ingress_v1".into(),
                            "attempt_admission_v1".into(),
                        ],
                    })
                })
            }
            fn endpoint(&self) -> crate::managed_state::RunEndpointPin {
                fake_run_endpoint(&self.binding)
            }
            fn pool_route(&self) -> crate::managed_state::Route {
                crate::managed_state::Route {
                    component_store_id: self.binding.pool_store_id.clone(),
                    route_id: "pool-route".into(),
                    worker_uid: self.binding.run_route.worker_uid,
                }
            }
            fn consume(
                &self,
                _: &crate::managed_bridge::ConsumeKey<'_>,
                _: &bridge_sdk::bridge_protocol::Secret,
                _: &str,
                _: &Command,
                _: &str,
            ) -> Result<crate::managed_bridge::Consumed, crate::managed_bridge::BridgeFailure>
            {
                self.later.fetch_add(1, Ordering::SeqCst);
                Err(crate::managed_bridge::BridgeFailure::Refused)
            }
        }
        let cases = [
            serde_json::json!({"name":"pool_post","arguments":{"pool_id":"pool","expected_revision":1,"request_key":"key","body":"body"}}),
            serde_json::json!({"name":"pool_vote","arguments":{"pool_id":"pool","expected_revision":1,"request_key":"key","proposal_id":"proposal","roster_key":"roster","choice":"ready","evidence":"evidence"}}),
            serde_json::json!({"name":"pool_propose","arguments":{"pool_id":"pool","expected_revision":1,"request_key":"key","result":"result","criteria":"criteria"}}),
            serde_json::json!({"name":"pool_remove","arguments":{"pool_id":"pool","expected_revision":1,"request_key":"key","member_id":"member"}}),
            serde_json::json!({"name":"pool_send_member","arguments":{"pool_id":"pool","expected_revision":1,"request_key":"key","member_id":"member","body":"body"}}),
            serde_json::json!({"name":"pool_notify_owner","arguments":{"pool_id":"pool","expected_revision":1,"request_key":"key","body":"body"}}),
            serde_json::json!({"name":"pool_get","arguments":{"pool_id":"pool"}}),
            serde_json::json!({"name":"pool_list","arguments":{}}),
        ];
        for value in cases {
            let (_directory, initial, binding, _, _) = fixture();
            let (command, normalized) = crate::managed_codec::normalize_command(value)?;
            let pin = fake_bridge_pin(&binding);
            let mut config = fake_config(&binding);
            let transport = config.managed_run_transport.as_mut().ok_or("transport")?;
            transport.frontend_enabled = true;
            transport.mcp_server = Some("pool".into());
            let begin = crate::managed_session::Begin {
                version: 1,
                bootstrap_id: "bootstrap".into(),
                invocation_key: "inv".into(),
                command: normalized.clone(),
                proof: native_proof(),
                bridge_pin: pin.clone(),
            };
            let store = Arc::new(Mutex::new(initial));
            let activity = Arc::new(ManagedActivity::default());
            let lease = activity
                .acquire(ManagedWork::Bootstrap("bootstrap".into()))?
                .ok_or("lease")?;
            let fake = Refusing {
                binding,
                checks: Arc::new(AtomicUsize::new(0)),
                later: Arc::new(AtomicUsize::new(0)),
            };
            let service = fake.clone();
            let task_store = Arc::clone(&store);
            let task_activity = Arc::clone(&activity);
            let (mut client, mut server) = UnixStream::pair()?;
            let task = tokio::spawn(async move {
                managed_session_core(
                    &mut server,
                    &config,
                    &task_store,
                    &task_activity,
                    begin,
                    command,
                    normalized,
                    pin,
                    lease,
                    service,
                )
                .await
            });
            assert!(matches!(
                crate::managed_session::receive::<crate::managed_session::ServerFrame>(&mut client)
                    .await?,
                crate::managed_session::ServerFrame::Ready
            ));
            crate::managed_session::send(
                &mut client,
                &crate::managed_session::ClientFrame::Epoch {
                    issuer_epoch: "epoch".into(),
                },
            )
            .await?;
            assert!(matches!(
                crate::managed_session::receive::<crate::managed_session::ServerFrame>(&mut client)
                    .await?,
                crate::managed_session::ServerFrame::Reserved
            ));
            crate::managed_session::send(
                &mut client,
                &crate::managed_session::ClientFrame::Prepared {
                    store_id: fake.binding.bridge_route.component_store_id.clone(),
                    bridge_context_ref: bridge_sdk::bridge_protocol::Secret::new("ref"),
                    invocation_key: "inv".into(),
                    expires_at_ms: 1,
                },
            )
            .await?;
            assert_eq!(task.await?.err(), Some(Fault::Unavailable));
            assert_eq!(fake.checks.load(Ordering::SeqCst), 2);
            assert_eq!(fake.later.load(Ordering::SeqCst), 0);
            let unchanged = stored(&store, |store| {
                let db = store.test_db();
                Ok(db.query_row("SELECT (SELECT count(*) FROM managed_contexts),(SELECT count(*) FROM managed_intents),(SELECT count(*) FROM events),(SELECT count(*) FROM effects)",[],|row|Ok((row.get::<_,i64>(0)?,row.get::<_,i64>(1)?,row.get::<_,i64>(2)?,row.get::<_,i64>(3)?)))?)
            }).await?;
            assert_eq!(unchanged, (0, 0, 0, 0));
        }
        Ok(())
    }

    /// A not-ready Run response retries the same staged original observation.
    #[tokio::test]
    async fn early_hook_reuses_original_staged_ingress_before_initial_binding()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::managed_state::tests::{
            fake_bridge_pin, fake_run_endpoint, fixture, native_proof,
        };
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct FakeIngress {
            calls: AtomicUsize,
            first_query: AtomicUsize,
            authority: Mutex<Option<crate::managed_run::CurrentAuthority>>,
        }
        impl managed_dispatch::IngressClient for FakeIngress {
            fn current<'a>(
                &'a self,
                query: &'a crate::managed_run::IngressQuery,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<
                            Output = Result<
                                crate::managed_run::CurrentAuthority,
                                crate::managed_run::RunError,
                            >,
                        > + Send
                        + 'a,
                >,
            > {
                Box::pin(async move {
                    let address = query as *const crate::managed_run::IngressQuery as usize;
                    let call = self.calls.fetch_add(1, Ordering::SeqCst);
                    if call == 0 {
                        self.first_query.store(address, Ordering::SeqCst);
                        return Err(crate::managed_run::RunError::NotReady);
                    }
                    assert_eq!(self.first_query.load(Ordering::SeqCst), address);
                    self.authority
                        .lock()
                        .map_err(|_| crate::managed_run::RunError::Unknown)?
                        .take()
                        .ok_or(crate::managed_run::RunError::Unknown)
                })
            }
        }

        let (_directory, mut initial, binding, _incarnation, run) = fixture();
        let db = initial.test_db();
        db.execute("DELETE FROM managed_bindings WHERE member='member'", [])?;
        let raw: String =
            db.query_row("SELECT data FROM members WHERE id='member'", [], |row| {
                row.get(0)
            })?;
        let mut member: Binding = serde_json::from_str(&raw)?;
        member.run_id = Some(binding.attempt.execution_id.clone());
        member.run_store_id = Some(binding.attempt.run_store_id.clone());
        db.execute(
            "UPDATE members SET data=?1,address=?2 WHERE id='member'",
            rusqlite::params![serde_json::to_string(&member)?, binding.actor.address],
        )?;
        let command = Command::List(crate::domain::List { after: None });
        let bridge_pin = fake_bridge_pin(&binding);
        let proof = native_proof();
        crate::managed_state::reserve_bootstrap(
            db,
            &crate::managed_state::BootstrapRequest {
                namespace_id: "namespace",
                bootstrap_id: "bootstrap",
                route: &binding.bridge_route,
                bridge_pin: &bridge_pin,
                producer: "pool",
                issuer_epoch: "epoch",
                invocation_key: "inv",
                command: &command,
                native_proof: &proof,
            },
        )?;
        let dispatch = crate::managed_state::mark_bootstrap_submitted(db, "bootstrap")?;
        crate::managed_state::record_bootstrap_ref(
            db,
            dispatch,
            &crate::managed_bridge::Prepared {
                store_id: binding.bridge_route.component_store_id.clone(),
                bridge_context_ref: bridge_sdk::bridge_protocol::Secret::new("original-ref"),
                invocation_key: "inv".into(),
                expires_at_ms: 100,
            },
            &bridge_pin,
        )?;
        let pin = crate::managed_state::RunPin {
            route: binding.run_route.clone(),
            socket: "/fixture/attempt.sock".into(),
            executable: "/fixture/run".into(),
            executable_sha256: "a".repeat(64),
            capabilities: vec!["attempt_current_ingress_v1".into()],
        };
        let intent = crate::managed_state::CurrentIntent::Ingress {
            version: 1,
            expected_store_id: binding.attempt.run_store_id.clone(),
            request_id: "current-key".into(),
            observation_ref: bridge_sdk::bridge_protocol::Secret::new("original-ref"),
            invocation_key: "inv".into(),
        };
        let intent_value = serde_json::to_value(&intent)?;
        let authority = crate::managed_run::CurrentAuthority::fixture(
            fake_run_endpoint(&binding),
            run.receipt.clone(),
            "inv",
            "current-key",
            intent_value.clone(),
        );
        let mut foreign = run.receipt.clone();
        foreign.lineage_root_id = "foreign".into();
        foreign.bound_execution_id = "foreign".into();
        foreign.attempt.lineage_root_id = "foreign".into();
        foreign.attempt.execution_id = "foreign".into();
        foreign.successor_proof.lineage_root_id = "foreign".into();
        foreign.successor_proof.bound_execution_id = "foreign".into();
        foreign.successor_proof.current_execution_id = "foreign".into();
        foreign.successor_proof.chain[0].execution_id = "foreign".into();
        let foreign_authority = crate::managed_run::CurrentAuthority::fixture(
            fake_run_endpoint(&binding),
            foreign,
            "inv",
            "current-key",
            intent_value,
        );
        let input = crate::managed_run::IngressInput {
            bridge_route: binding.bridge_route.clone(),
            producer: "pool".into(),
            observation_ref: bridge_sdk::bridge_protocol::Secret::new("original-ref"),
            invocation_key: "inv".into(),
            request_id: "current-key".into(),
            transport_id: "current-rpc".into(),
        };
        let fake = FakeIngress {
            calls: AtomicUsize::new(0),
            first_query: AtomicUsize::new(0),
            authority: Mutex::new(Some(authority)),
        };
        let store = Arc::new(Mutex::new(initial));
        let activity = Arc::new(ManagedActivity::default());
        let lease = activity
            .acquire(ManagedWork::Bootstrap("bootstrap".into()))?
            .ok_or("bootstrap lease")?;
        let authority = managed_dispatch::ingress(
            &store,
            &activity,
            &lease,
            "bootstrap".into(),
            pin,
            input,
            &fake,
        )
        .await?;
        assert_eq!(fake.calls.load(Ordering::SeqCst), 2);
        let bridge_route = binding.bridge_route.clone();
        let selected = stored_managed(&store, &lease, move |store| {
            assert_eq!(
                store
                    .managed_select_ingress_binding(
                        &foreign_authority,
                        &bridge_route,
                        "pool",
                        &command
                    )
                    .err(),
                Some(Fault::Forbidden)
            );
            store.managed_select_ingress_binding(&authority, &bridge_route, "pool", &command)
        })
        .await?;
        assert_eq!(selected, binding);
        Ok(())
    }

    /// A superseded voter is rebound through a separate pinned egress observation before aborting the old CAS.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn consensus_superseded_rebinds_before_rejecting_old_vote()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::managed_state::tests::{
            consumed_admission, fake_config, fixture_with_uid, index_managed_member,
            prepare_command, reserve,
        };
        use managed_dispatch::Client;
        use sha2::Digest;
        let _hash_guard = crate::TEST_EXEC_HASH_LOCK.lock().await;
        let uid = fs::metadata(std::env::var_os("TMPDIR").ok_or("TMPDIR")?)?.uid();
        let (directory, mut initial, binding, incarnation, run) = fixture_with_uid(uid);
        let socket = directory.path().join("attempt.sock");
        let listener = UnixListener::bind(&socket)?;
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
        let executable = std::env::current_exe()?;
        let sha256 = format!("{:x}", sha2::Sha256::digest(fs::read(&executable)?));
        let endpoint = crate::managed_state::RunEndpointPin {
            route: binding.run_route.clone(),
            socket: socket.clone(),
            executable: executable.clone(),
            executable_sha256: sha256.clone(),
        };
        let db = initial.test_db();
        db.execute("DELETE FROM managed_run_routes", [])?;
        crate::managed_state::persist_run_route(db, &endpoint)?;
        index_managed_member(db, &binding);
        let raw: String =
            db.query_row("SELECT data FROM members WHERE id='member'", [], |row| {
                row.get(0)
            })?;
        let mut member: Binding = serde_json::from_str(&raw)?;
        member.member.state = crate::domain::MemberState::Active;
        db.execute(
            "UPDATE members SET data=?1 WHERE id='member'",
            [serde_json::to_string(&member)?],
        )?;
        let raw: String = db.query_row("SELECT data FROM pools WHERE id='pool'", [], |row| {
            row.get(0)
        })?;
        let mut pool: crate::domain::Pool = serde_json::from_str(&raw)?;
        pool.proposal = Some(crate::domain::Proposal {
            proposal_id: "proposal".into(),
            roster_key: "roster".into(),
            voters: vec!["member".into()],
            result: "result".into(),
            criteria: "criteria".into(),
            snapshot: None,
            snapshot_bytes: None,
            state: crate::domain::ProposalState::Open,
            votes: std::collections::BTreeMap::new(),
        });
        db.execute(
            "INSERT INTO proposals(id,pool,state,data) VALUES('proposal','pool','open',?1)",
            [serde_json::to_string(
                pool.proposal.as_ref().ok_or("proposal")?,
            )?],
        )?;
        db.execute(
            "UPDATE pools SET data=?1 WHERE id='pool'",
            [serde_json::to_string(&pool)?],
        )?;
        let vote = Command::Vote(crate::domain::Vote {
            change: crate::domain::Change {
                pool_id: "pool".into(),
                expected_revision: 1,
                request_key: "vote-key".into(),
            },
            proposal_id: "proposal".into(),
            roster_key: "roster".into(),
            choice: crate::domain::Choice::Ready,
            evidence: "ready".into(),
            checks: vec![],
        });
        let digest = prepare_command(
            db,
            &run,
            &binding,
            &incarnation,
            "vote-context",
            "vote-intent",
            "vote-inv",
            &vote,
        );
        assert_eq!(
            reserve(
                db,
                &run,
                &binding,
                &incarnation,
                "vote-context",
                "vote-inv",
                "vote-intent",
                &vote,
                &digest
            )?,
            crate::managed_state::IntentReservation::Created
        );
        let admission = consumed_admission(
            db,
            &run,
            &binding,
            &incarnation,
            "vote-intent",
            "vote-inv",
            &digest,
            &vote,
        );
        crate::managed_state::mark_admitted(db, "vote-intent", &digest, &admission)?;
        let pending = crate::managed_state::snapshot_consensus(db, "vote-intent", &digest)?;
        let mut successor = binding.attempt.clone();
        successor.attempt_id = "attempt-2".into();
        successor.launch_id = "00000000-0000-4000-8000-000000000004".into();
        let mut next = incarnation.clone();
        next.pid += 1;
        next.start_ticks += 1;
        let mut egress = run.receipt.clone();
        egress.receipt_id = "egress-r2".into();
        egress.purpose = "egress".into();
        egress.attempt = successor.clone();
        egress.incarnation = next.clone();
        let store_id = binding.run_route.component_store_id.clone();
        let server = tokio::spawn(async move {
            for index in 0..8 {
                let (mut stream, _) = listener.accept().await.map_err(|_| Fault::Unavailable)?;
                let request: serde_json::Value =
                    serde_json::from_slice(&integrations::read_frame(&mut stream).await?)
                        .map_err(|_| Fault::Invalid)?;
                let value = match index {
                    0 | 1 | 3 | 4 | 6 => {
                        assert_eq!(request["method"], "_attempt_capabilities_v1");
                        serde_json::json!({"version":1,"store_id":store_id,"capabilities":["attempt_consensus_v1","attempt_current_egress_v1"],"policy":"admission_snapshot"})
                    }
                    2 => {
                        assert_eq!(request["params"]["purpose"], "consensus");
                        serde_json::json!({"version":1,"store_id":store_id,"state":"superseded","last_attempt":successor,"last_incarnation":next,"successor_proof":egress.successor_proof})
                    }
                    5 => {
                        assert_eq!(request["params"]["purpose"], "egress");
                        serde_json::json!({"version":1,"store_id":store_id,"state":"current","receipt":egress})
                    }
                    _ => {
                        assert_eq!(request["method"], "_attempt_current_receipt_v1");
                        serde_json::json!({"version":1,"store_id":store_id,"receipt":egress})
                    }
                };
                let response = serde_json::json!({"id":request["id"],"result":value});
                stream
                    .write_all(format!("{response}\n").as_bytes())
                    .await
                    .map_err(|_| Fault::Unavailable)?;
            }
            Ok::<(), Fault>(())
        });
        let mut config = fake_config(&binding);
        let transport = config.managed_run_transport.as_mut().ok_or("transport")?;
        transport.socket = socket;
        transport.executable = executable;
        transport.sha256 = sha256;
        let store = Arc::new(Mutex::new(initial));
        let activity = Arc::new(ManagedActivity::default());
        let lease = activity
            .acquire(ManagedWork::Intent("vote-intent".into()))?
            .ok_or("lease")?;
        let client = managed_dispatch::ConfiguredClient { config: &config };
        assert_eq!(
            client.consensus(pending, &store, &lease).await.err(),
            Some(Fault::Stale)
        );
        server.await??;
        let (generation, context, revision) = stored(&store, |store| {
            Ok(store.test_db().query_row(
                "SELECT b.generation,c.state,json_extract(p.data,'$.revision') FROM managed_bindings b JOIN managed_contexts c ON c.id='vote-context' JOIN pools p ON p.id=b.pool WHERE b.member='member'",
                [], |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?, row.get::<_, i64>(2)?)),
            )?)
        }).await?;
        assert_eq!(generation, 2u64.to_be_bytes());
        assert_eq!(context, "invalidated");
        assert_eq!(revision, 1);
        Ok(())
    }

    /// After an upgrade moved the Bridge and Run executables, the stale stored pin refuses
    /// the managed delivery with route attention while the resident worker keeps running;
    /// after `repin` the same delivery proceeds on the new pin.
    #[tokio::test]
    async fn stale_route_pin_refuses_managed_delivery_without_stopping_resident()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::managed_egress::tests::add_seed;
        use crate::managed_state::tests::{fake_config, fixture_with_uid, index_managed_member};
        let uid = fs::metadata(std::env::var_os("TMPDIR").ok_or("task TMPDIR required")?)?.uid();
        let (dir, mut initial, binding, _incarnation, _run) = fixture_with_uid(uid);
        index_managed_member(initial.test_db(), &binding);
        add_seed(&mut initial, &binding, "stale-effect", "payload", false);
        initial.test_db().execute(
            "UPDATE effects SET state='awaiting_binding' WHERE id='stale-effect'",
            [],
        )?;
        let root = fs::canonicalize(dir.path())?;
        let mut config = fake_config(&binding);
        config.socket_path = root.join("pool.sock");
        config.database_path = root.join("pool.db");
        config.bridge_registration_socket = root.join("adapter.sock");
        config.bridge_core_socket = root.join("core.sock");
        config.bridge_credential_file = root.join("token");
        config.bridge_server_executable =
            "/opt/agent-bridge/releases/0.7.1+b2666a5d02f8/bin/bridge-native-daemon".into();
        config.bridge_server_sha256 = "d".repeat(64);
        let _adapter = std::os::unix::net::UnixListener::bind(&config.bridge_registration_socket)?;
        let _core = std::os::unix::net::UnixListener::bind(&config.bridge_core_socket)?;
        for socket in [
            &config.bridge_registration_socket,
            &config.bridge_core_socket,
        ] {
            fs::set_permissions(socket, fs::Permissions::from_mode(0o600))?;
        }
        fs::write(&config.bridge_credential_file, "fixture-credential")?;
        fs::set_permissions(
            &config.bridge_credential_file,
            fs::Permissions::from_mode(0o600),
        )?;
        let transport = config.managed_run_transport.as_mut().ok_or("transport")?;
        transport.egress_enabled = true;
        transport.producer_scope_prefix = Some(format!("pool/{}/", binding.pool_store_id));
        transport.socket = root.join("run").join("attempt.sock");
        transport.executable = "/opt/agent-run/releases/0.2.0/bin/agent-run".into();
        transport.sha256 = "c".repeat(64);

        // The store still holds the pre-upgrade pins: same routes and sockets, old executables.
        let (_, upgraded_bridge) =
            crate::managed_bridge::SdkBridge::capture(&config, binding.bridge_route.clone())
                .map_err(|error| format!("capture: {error}"))?;
        let peer = crate::managed_run::RunPeer::from_config(&config, &binding.pool_store_id)
            .map_err(|_| "peer config")?;
        let upgraded_run = peer.endpoint_pin();
        let mut old_bridge = upgraded_bridge.clone();
        old_bridge.server_executable =
            "/opt/agent-bridge/releases/0.7.0+0123456789ab/bin/bridge-native-daemon".into();
        old_bridge.server_sha256 = "a".repeat(64);
        let mut old_run = upgraded_run.clone();
        old_run.executable = "/opt/agent-run/releases/0.1.0/bin/agent-run".into();
        old_run.executable_sha256 = "a".repeat(64);
        let old_bridge_json = serde_json::to_string(&old_bridge)?;
        let old_run_json = serde_json::to_string(&old_run)?;
        let db = initial.test_db();
        db.execute(
            "UPDATE managed_bridge_routes SET pin=?1",
            [&old_bridge_json],
        )?;
        db.execute("UPDATE managed_run_routes SET pin=?1", [&old_run_json])?;
        db.execute(
            "UPDATE managed_route_pin_history SET pin=?1 WHERE kind='bridge'",
            [&old_bridge_json],
        )?;
        db.execute(
            "UPDATE managed_route_pin_history SET pin=?1 WHERE kind='run'",
            [&old_run_json],
        )?;
        let store = Arc::new(Mutex::new(initial));
        let attention = |store: SharedStore| async move {
            stored(&store, |store| {
                Ok(store.test_db().query_row::<Option<String>, _, _>(
                    "SELECT attention FROM managed_delivery_outbox WHERE effect_id='stale-effect'",
                    [],
                    |row| row.get(0),
                )?)
            })
            .await
        };
        let wait_for = |expected: &'static str| {
            let store = Arc::clone(&store);
            let config = config.clone();
            async move {
                let (stop, stopped) = watch::channel(false);
                let mut worker = tokio::spawn(fixture_work(config, Arc::clone(&store), stopped));
                let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
                while attention(Arc::clone(&store)).await?.as_deref() != Some(expected) {
                    assert!(!worker.is_finished(), "resident worker stopped early");
                    assert!(tokio::time::Instant::now() < deadline, "no {expected}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                assert!(!worker.is_finished(), "resident worker must keep running");
                stop.send(true)?;
                tokio::time::timeout(Duration::from_secs(20), &mut worker)
                    .await??
                    .map_err(|error| format!("resident worker: {error}"))?;
                Ok::<(), Box<dyn std::error::Error>>(())
            }
        };
        wait_for("route_unavailable").await?;
        let (bridge_pin, run_pin, generations) = stored(&store, |store| {
            let db = store.test_db();
            Ok((
                db.query_row::<String, _, _>("SELECT pin FROM managed_bridge_routes", [], |r| {
                    r.get(0)
                })?,
                db.query_row::<String, _, _>("SELECT pin FROM managed_run_routes", [], |r| {
                    r.get(0)
                })?,
                db.query_row::<i64, _, _>(
                    "SELECT MAX(generation) FROM managed_route_pin_history",
                    [],
                    |r| r.get(0),
                )?,
            ))
        })
        .await?;
        assert_eq!(
            (bridge_pin, run_pin, generations),
            (old_bridge_json, old_run_json, 1)
        );

        // The documented upgrade flow: repin, then the delivery uses the new pin and
        // reaches Run (absent here) instead of the stale-pin refusal.
        let pool_route = peer.pool_route.clone();
        assert_eq!(
            stored(&store, move |store| {
                store.managed_repin_routes(&upgraded_bridge, &upgraded_run, &pool_route, true)
            })
            .await?,
            (2, 2)
        );
        wait_for("binding_unavailable").await?;
        Ok(())
    }

    /// Synthetic Run and Bridge exercise relaunch, exact-target retry, unknown and retirement.
    #[tokio::test]
    async fn managed_egress_fake_run_bridge_recovery_never_resends_unknown()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::managed_egress::tests::{add_seed, pin, receipt, result};
        use crate::managed_egress::{Frozen, OwnerClient, OwnerFailure, ScopePlan, State};
        use crate::managed_state::tests::{
            fake_bridge_pin, fake_run_endpoint, fixture, index_managed_member,
        };
        use bridge_sdk::bridge_protocol::{
            RetireReceipt, RetireResult, RetirementAction,
            managed_owner::{
                CompactManagedOwnerScopeResultV1, ManagedOwnerResultV1, ManagedOwnerStateV1,
            },
        };
        use std::sync::atomic::{AtomicUsize, Ordering};
        #[derive(Clone)]
        struct FakeRun {
            binding: crate::managed_state::ManagedBinding,
            incarnation: crate::managed_state::Incarnation,
            requests: Arc<Mutex<Vec<String>>>,
        }
        impl managed_egress_dispatch::CurrentClient for FakeRun {
            fn endpoint(&self) -> crate::managed_state::RunEndpointPin {
                fake_run_endpoint(&self.binding)
            }
            fn pool_route(&self) -> crate::managed_state::Route {
                crate::managed_state::Route {
                    component_store_id: self.binding.pool_store_id.clone(),
                    route_id: "pool-route".into(),
                    worker_uid: self.binding.run_route.worker_uid,
                }
            }
            fn current_pin(
                &self,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<
                            Output = Result<
                                crate::managed_state::RunPin,
                                crate::managed_run::RunError,
                            >,
                        > + Send
                        + '_,
                >,
            > {
                Box::pin(async move { Ok(pin(&self.binding)) })
            }
            fn current<'a>(
                &'a self,
                query: &'a crate::managed_run::EgressQuery,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<
                            Output = Result<
                                crate::managed_run::CurrentAuthority,
                                crate::managed_run::RunError,
                            >,
                        > + Send
                        + 'a,
                >,
            > {
                Box::pin(async move {
                    let call = {
                        let mut requests = self
                            .requests
                            .lock()
                            .map_err(|_| crate::managed_run::RunError::Unknown)?;
                        requests.push(query.fixture_request_id().into());
                        requests.len()
                    };
                    if call <= 2 {
                        return Err(crate::managed_run::RunError::ActorRecovery(
                            crate::managed_run::ActorRecovery::AwaitingRootHook,
                        ));
                    }
                    if call == 3 {
                        return Err(crate::managed_run::RunError::ActorRecovery(
                            crate::managed_run::ActorRecovery::RelaunchRequired,
                        ));
                    }
                    if call == 4 {
                        return Err(crate::managed_run::RunError::BindingStale);
                    }
                    if call == 5 {
                        return Err(crate::managed_run::RunError::Unknown);
                    }
                    let current = receipt(
                        &self.binding,
                        &self.incarnation,
                        "next",
                        2,
                        &format!("receipt-{call}"),
                    );
                    query
                        .fixture_authority(current)
                        .map_err(|_| crate::managed_run::RunError::Unknown)
                })
            }
        }
        #[derive(Clone, Default)]
        struct FakeOwner {
            publishes: Arc<AtomicUsize>,
            lookups: Arc<AtomicUsize>,
            aborts: Arc<AtomicUsize>,
            retires: Arc<AtomicUsize>,
            compacts: Arc<AtomicUsize>,
            digests: Arc<Mutex<Vec<String>>>,
            retire_keys: Arc<Mutex<Vec<String>>>,
        }
        impl OwnerClient for FakeOwner {
            fn capabilities(&self, _: &str) -> Result<(), OwnerFailure> {
                Ok(())
            }
            fn publish(
                &self,
                _: &str,
                frozen: &Frozen,
            ) -> Result<ManagedOwnerResultV1, OwnerFailure> {
                self.digests
                    .lock()
                    .map_err(|_| OwnerFailure::Unknown)?
                    .push(frozen.digest.clone());
                if self.publishes.fetch_add(1, Ordering::SeqCst) == 0 {
                    Ok(result(
                        frozen,
                        ManagedOwnerStateV1::KnownUnsent,
                        Some("qualification_pending"),
                    ))
                } else {
                    Err(OwnerFailure::Unknown)
                }
            }
            fn lookup(
                &self,
                _: &str,
                frozen: &Frozen,
            ) -> Result<ManagedOwnerResultV1, OwnerFailure> {
                self.lookups.fetch_add(1, Ordering::SeqCst);
                Ok(result(
                    frozen,
                    ManagedOwnerStateV1::Unknown,
                    Some("native_uncertain"),
                ))
            }
            fn abort(
                &self,
                _: &str,
                frozen: &Frozen,
            ) -> Result<ManagedOwnerResultV1, OwnerFailure> {
                if self.aborts.fetch_add(1, Ordering::SeqCst) == 0 {
                    Err(OwnerFailure::Unknown)
                } else {
                    Ok(result(frozen, ManagedOwnerStateV1::Aborted, None))
                }
            }
            fn retire(
                &self,
                request: &str,
                scope: &ScopePlan,
            ) -> Result<RetireResult, OwnerFailure> {
                self.retire_keys
                    .lock()
                    .map_err(|_| OwnerFailure::Unknown)?
                    .push(request.into());
                if self.retires.fetch_add(1, Ordering::SeqCst) == 0 {
                    return Err(OwnerFailure::Unknown);
                }
                Ok(RetireResult {
                    receipt: RetireReceipt {
                        producer: scope.bridge_pin.producer.clone(),
                        request_id: scope.retire_request_id.clone(),
                        scope_key: scope.producer_scope.clone(),
                        action: RetirementAction::RetireUnhanded,
                        retired_at_ms: 1,
                        disposed: 0,
                        already_terminal: 1,
                        preserved_possible_effect: 0,
                        preserved_unhanded: 0,
                    },
                    replayed: false,
                })
            }
            fn compact(
                &self,
                _: &str,
                scope: &ScopePlan,
            ) -> Result<CompactManagedOwnerScopeResultV1, OwnerFailure> {
                self.compacts.fetch_add(1, Ordering::SeqCst);
                Ok(CompactManagedOwnerScopeResultV1 {
                    version: 1,
                    store_id: scope.bridge_pin.route.component_store_id.clone(),
                    producer: scope.bridge_pin.producer.clone(),
                    producer_scope: scope.producer_scope.clone(),
                    compacted: 1,
                    remaining: 0,
                })
            }
        }
        let (_dir, mut initial, binding, incarnation, _run) = fixture();
        index_managed_member(initial.test_db(), &binding);
        add_seed(&mut initial, &binding, "fake-effect", "payload", false);
        let store = Arc::new(Mutex::new(initial));
        let activity = Arc::new(ManagedActivity::default());
        let lease = activity
            .acquire(ManagedWork::Egress("fake-effect".into()))?
            .ok_or("effect lease")?;
        let prefix = format!("pool/{}/", binding.pool_store_id);
        let target = stored_managed(&store, &lease, {
            let prefix = prefix.clone();
            move |store| store.egress_target("fake-effect", &prefix)
        })
        .await?;
        let run = FakeRun {
            binding: binding.clone(),
            incarnation,
            requests: Arc::new(Mutex::new(Vec::new())),
        };
        let bridge_pin = fake_bridge_pin(&binding);
        assert!(
            managed_egress_dispatch::freeze_target(
                &store,
                &lease,
                target.clone(),
                prefix.clone(),
                &run,
                bridge_pin.clone(),
                "pool".into()
            )
            .await?
            .is_none()
        );
        for _ in 0..2 {
            assert!(
                managed_egress_dispatch::freeze_target(
                    &store,
                    &lease,
                    target.clone(),
                    prefix.clone(),
                    &run,
                    bridge_pin.clone(),
                    "pool".into(),
                )
                .await?
                .is_none()
            );
        }
        let attention = stored_managed(&store, &lease, |store| {
            Ok(store.test_db().query_row::<String, _, _>(
                "SELECT attention FROM managed_delivery_outbox WHERE effect_id='fake-effect'",
                [],
                |row| row.get(0),
            )?)
        })
        .await?;
        assert_eq!(attention, "actor_relaunch_required");
        let observed = stored_managed(&store,&lease,|store| {
            let request:crate::observer::Request=serde_json::from_value(serde_json::json!({"schema_version":1,"operation":"get","params":{"pool_id":"pool","section":"deliveries"}})).map_err(|_|Fault::Invalid)?;
            let crate::observer::Data::Detail(detail)=store.observe(&request)? else{return Err(Fault::Internal)};
            Ok(detail.view.and_then(|view|view.deliveries.into_iter().find(|delivery|delivery.operation_id=="fake-effect")).map(|delivery|(delivery.attention,delivery.attention_subject)))
        }).await?;
        assert_eq!(
            observed,
            Some((Some("relaunch_required".into()), Some("member".into())))
        );
        let resident_attention = stored_managed(&store, &lease, |store| {
            store.egress_attention("fake-effect", "relaunch_required")?;
            crate::managed_egress::owner_attention(store.test_db(), "fake-effect")
        })
        .await?;
        assert_eq!(
            resident_attention,
            (Some("relaunch_required".into()), Some("resident".into()))
        );
        // Run reports the old launch stale after relaunch. That call must use
        // the old key; only the following observation gets a fresh key.
        assert!(
            managed_egress_dispatch::freeze_target(
                &store,
                &lease,
                target.clone(),
                prefix.clone(),
                &run,
                bridge_pin.clone(),
                "pool".into(),
            )
            .await?
            .is_none()
        );
        // Lost currentness ACK: look up the original key, but discard a
        // possibly historical receipt and obtain fresh evidence under a new key.
        for _ in 0..2 {
            assert!(
                managed_egress_dispatch::freeze_target(
                    &store,
                    &lease,
                    target.clone(),
                    prefix.clone(),
                    &run,
                    bridge_pin.clone(),
                    "pool".into(),
                )
                .await?
                .is_none()
            );
        }
        let frozen = managed_egress_dispatch::freeze_target(
            &store,
            &lease,
            target,
            prefix,
            &run,
            bridge_pin.clone(),
            "pool".into(),
        )
        .await?
        .ok_or("fresh target")?;
        let requests = run.requests.lock().map_err(|_| "requests")?.clone();
        assert_eq!(requests.len(), 7);
        assert!(requests[..4].iter().all(|id| id == &requests[0]));
        assert_ne!(requests[0], requests[4]);
        assert_eq!(requests[4], requests[5]);
        assert_ne!(requests[5], requests[6]);
        let bridge = FakeOwner::default();
        managed_egress_dispatch::publish(&store, &lease, frozen.clone(), bridge.clone()).await?;
        assert_eq!(
            stored_managed(&store, &lease, |store| store.egress_state("fake-effect")).await?,
            Some(State::KnownUnsent)
        );
        managed_egress_dispatch::publish(&store, &lease, frozen.clone(), bridge.clone()).await?;
        assert_eq!(
            stored_managed(&store, &lease, |store| store.egress_state("fake-effect")).await?,
            Some(State::Unknown)
        );
        managed_egress_dispatch::reconcile(&store, &lease, frozen.clone(), bridge.clone(), false)
            .await?;
        assert_eq!(bridge.publishes.load(Ordering::SeqCst), 2);
        assert_eq!(bridge.lookups.load(Ordering::SeqCst), 1);
        assert_eq!(
            bridge.digests.lock().map_err(|_| "digests")?.as_slice(),
            [frozen.digest.clone(), frozen.digest.clone()]
        );
        stored_managed(&store, &lease, |store| {
            crate::managed_egress::retire_member_scope(store.test_db(), "pool", "member")
        })
        .await?;
        managed_egress_dispatch::reconcile(&store, &lease, frozen.clone(), bridge.clone(), true)
            .await?;
        assert_eq!(
            stored_managed(&store, &lease, |store| store.egress_state("fake-effect")).await?,
            Some(State::AbortPending)
        );
        managed_egress_dispatch::reconcile(&store, &lease, frozen.clone(), bridge.clone(), true)
            .await?;
        assert_eq!(
            stored_managed(&store, &lease, |store| store.egress_state("fake-effect")).await?,
            Some(State::Aborted)
        );
        assert_eq!(bridge.publishes.load(Ordering::SeqCst), 2);
        drop(lease);
        let scope_id = frozen.seed.producer_scope.clone();
        let scope_lease = activity
            .acquire(ManagedWork::EgressScope(scope_id.clone()))?
            .ok_or("scope lease")?;
        let plan = stored_managed(&store, &scope_lease, {
            let scope_id = scope_id.clone();
            let bridge_pin = bridge_pin.clone();
            move |store| store.egress_prepare_scope(&scope_id, &bridge_pin, "pool")
        })
        .await?;
        managed_egress_dispatch::scope(&store, &scope_lease, plan, bridge.clone()).await?;
        let retiring = stored_managed(&store, &scope_lease, {
            let scope_id = scope_id.clone();
            move |store| {
                Ok(store.test_db().query_row::<String, _, _>(
                    "SELECT state FROM managed_delivery_scopes WHERE producer_scope=?1",
                    [scope_id],
                    |row| row.get(0),
                )?)
            }
        })
        .await?;
        assert_eq!(retiring, "retiring");
        let plan = stored_managed(&store, &scope_lease, {
            let scope_id = scope_id.clone();
            let bridge_pin = bridge_pin.clone();
            move |store| store.egress_prepare_scope(&scope_id, &bridge_pin, "pool")
        })
        .await?;
        managed_egress_dispatch::scope(&store, &scope_lease, plan, bridge.clone()).await?;
        let plan = stored_managed(&store, &scope_lease, {
            let scope_id = scope_id.clone();
            move |store| store.egress_prepare_scope(&scope_id, &bridge_pin, "pool")
        })
        .await?;
        managed_egress_dispatch::scope(&store, &scope_lease, plan, bridge.clone()).await?;
        assert_eq!(bridge.retires.load(Ordering::SeqCst), 2);
        {
            let retire_keys = bridge.retire_keys.lock().map_err(|_| "retire keys")?;
            assert_eq!(retire_keys.len(), 2);
            assert_eq!(retire_keys[0], retire_keys[1]);
        }
        assert_eq!(bridge.compacts.load(Ordering::SeqCst), 1);
        let scope_state = stored_managed(&store, &scope_lease, move |store| {
            Ok(store.test_db().query_row::<String, _, _>(
                "SELECT state FROM managed_delivery_scopes WHERE producer_scope=?1",
                [scope_id],
                |row| row.get(0),
            )?)
        })
        .await?;
        assert_eq!(scope_state, "compacted");
        Ok(())
    }

    #[tokio::test]
    async fn final_notice_foreign_lineage_is_definitively_not_delivered()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::managed_egress::tests::{add_seed, pin};
        use crate::managed_state::tests::{
            fake_bridge_pin, fake_run_endpoint, fixture, index_managed_member,
        };
        struct Foreign {
            binding: crate::managed_state::ManagedBinding,
        }
        impl managed_egress_dispatch::CurrentClient for Foreign {
            fn endpoint(&self) -> crate::managed_state::RunEndpointPin {
                fake_run_endpoint(&self.binding)
            }
            fn pool_route(&self) -> crate::managed_state::Route {
                crate::managed_state::Route {
                    component_store_id: self.binding.pool_store_id.clone(),
                    route_id: "pool-route".into(),
                    worker_uid: self.binding.run_route.worker_uid,
                }
            }
            fn current_pin(
                &self,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<
                            Output = Result<
                                crate::managed_state::RunPin,
                                crate::managed_run::RunError,
                            >,
                        > + Send
                        + '_,
                >,
            > {
                Box::pin(async move { Ok(pin(&self.binding)) })
            }
            fn current<'a>(
                &'a self,
                _: &'a crate::managed_run::EgressQuery,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<
                            Output = Result<
                                crate::managed_run::CurrentAuthority,
                                crate::managed_run::RunError,
                            >,
                        > + Send
                        + 'a,
                >,
            > {
                Box::pin(async move { Err(crate::managed_run::RunError::DifferentLineage) })
            }
        }
        let (_dir, mut initial, binding, _incarnation, _run) = fixture();
        index_managed_member(initial.test_db(), &binding);
        initial
            .test_db()
            .execute("UPDATE members SET current=0 WHERE id='member'", [])?;
        add_seed(
            &mut initial,
            &binding,
            "final-foreign",
            "final notice",
            true,
        );
        let store = Arc::new(Mutex::new(initial));
        let activity = Arc::new(ManagedActivity::default());
        let lease = activity
            .acquire(ManagedWork::Egress("final-foreign".into()))?
            .ok_or("lease")?;
        let prefix = format!("pool/{}/", binding.pool_store_id);
        let target = stored_managed(&store, &lease, {
            let prefix = prefix.clone();
            move |store| store.egress_target("final-foreign", &prefix)
        })
        .await?;
        let bridge = fake_bridge_pin(&binding);
        assert!(
            managed_egress_dispatch::freeze_target(
                &store,
                &lease,
                target,
                prefix,
                &Foreign { binding },
                bridge,
                "pool".into()
            )
            .await?
            .is_none()
        );
        let result=stored_managed(&store,&lease,|store|Ok(store.test_db().query_row::<(String,String),_,_>("SELECT state,attention FROM managed_delivery_outbox WHERE effect_id='final-foreign'",[],|row|Ok((row.get(0)?,row.get(1)?)))?)).await?;
        assert_eq!(result, ("not_delivered".into(), "different_lineage".into()));
        Ok(())
    }

    /// Managed reads remain on the authenticated bootstrap lease and keep Bridge cleanup pending.
    #[tokio::test]
    async fn managed_read_dispatch_uses_lease_and_preserves_bridge_cleanup()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::managed_state::tests::{
            fake_consumed, fixture, fresh_authority, index_managed_member, prepare_command,
        };
        let (_directory, mut initial, binding, incarnation, run) = fixture();
        let db = initial.test_db();
        index_managed_member(db, &binding);
        let command: Command = serde_json::from_value(
            serde_json::json!({"name":"pool_get","arguments":{"pool_id":"pool"}}),
        )?;
        let digest = prepare_command(
            db,
            &run,
            &binding,
            &incarnation,
            "read-context",
            "read-intent",
            "read-inv",
            &command,
        );
        let authority = fresh_authority(db, &binding, "read-context", "read-inv")?;
        let consumed = fake_consumed(
            &binding,
            &incarnation,
            "read-intent",
            "read-inv",
            &digest,
            &command,
        );
        let store = Arc::new(Mutex::new(initial));
        let activity = Arc::new(ManagedActivity::default());
        let lease = activity
            .acquire(ManagedWork::Bootstrap("read-context".into()))?
            .ok_or("read lease")?;
        let reply = managed_dispatch::read(
            &store,
            &activity,
            &lease,
            managed_dispatch::Read {
                bootstrap_id: "read-context".into(),
                context_id: "read-context".into(),
                command,
                digest: digest.clone(),
                authorities: vec![authority],
                consumed,
            },
        )
        .await?;
        let Reply::View(view) = reply else {
            return Err("expected participant view".into());
        };
        assert_eq!(view.pool.pool_id, "pool");
        let action = stored_managed(&store, &lease, |store| {
            store.managed_stage_bootstrap("read-context")
        })
        .await?;
        let crate::managed_state::BootstrapRecoveryAction::BridgeAbort { key, .. } = action else {
            return Err("expected exact Bridge abort".into());
        };
        assert_eq!(key.security_digest, digest);
        assert_eq!(key.consume_request_id, "read-intent");
        Ok(())
    }

    /// Two fresh invocations share one domain key and submit only one Run admission.
    #[tokio::test]
    async fn managed_dispatch_concurrent_key_admits_and_commits_once()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::managed_state::tests::{
            FakeRun, consumed_admission, fake_consumed, fixture, fresh_authority,
            index_managed_member, prepare_command,
        };
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        struct FakeBridge {
            receipts: std::collections::BTreeMap<String, crate::managed_bridge::Consumed>,
        }
        impl crate::managed_bridge::BridgeB1Client for FakeBridge {
            fn capabilities(
                &self,
            ) -> Result<crate::managed_bridge::Capabilities, crate::managed_bridge::BridgeFailure>
            {
                Err(crate::managed_bridge::BridgeFailure::Refused)
            }
            fn prepare(
                &self,
                _: &crate::managed_bridge::Prepare<'_>,
            ) -> Result<crate::managed_bridge::Prepared, crate::managed_bridge::BridgeFailure>
            {
                Err(crate::managed_bridge::BridgeFailure::Refused)
            }
            fn register(
                &self,
                _: &crate::managed_bridge::Registration<'_>,
            ) -> Result<crate::managed_bridge::Registered, crate::managed_bridge::BridgeFailure>
            {
                Err(crate::managed_bridge::BridgeFailure::Refused)
            }
            fn consume(
                &self,
                key: &crate::managed_bridge::ConsumeKey<'_>,
                _: &bridge_sdk::bridge_protocol::Secret,
            ) -> Result<crate::managed_bridge::Consumed, crate::managed_bridge::BridgeFailure>
            {
                self.receipts
                    .get(key.consume_request_id)
                    .cloned()
                    .ok_or(crate::managed_bridge::BridgeFailure::Refused)
            }
            fn lookup(
                &self,
                _: &str,
                _: &crate::managed_bridge::ConsumeKey<'_>,
            ) -> Result<crate::managed_bridge::Consumed, crate::managed_bridge::BridgeFailure>
            {
                Err(crate::managed_bridge::BridgeFailure::Refused)
            }
            fn abort(
                &self,
                key: &crate::managed_bridge::ConsumeKey<'_>,
            ) -> Result<crate::managed_bridge::Abort, crate::managed_bridge::BridgeFailure>
            {
                let receipt = self
                    .receipts
                    .get(key.consume_request_id)
                    .ok_or(crate::managed_bridge::BridgeFailure::Refused)?;
                Ok(crate::managed_bridge::Abort {
                    store_id: key.expected_store_id.into(),
                    aborted: true,
                    receipt: Some(receipt.receipt.clone()),
                })
            }
        }
        struct FakeClient {
            admission: crate::managed_run::Admission,
            run: FakeRun,
            calls: AtomicUsize,
            fail: AtomicBool,
            not_ready_once: AtomicBool,
            entered: tokio::sync::Notify,
            release: tokio::sync::Notify,
        }
        impl managed_dispatch::Client for FakeClient {
            fn admit<'a>(
                &'a self,
                plan: &'a crate::managed_state::AdmissionPlan,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<
                            Output = Result<
                                crate::managed_run::Admission,
                                crate::managed_run::RunError,
                            >,
                        > + Send
                        + 'a,
                >,
            > {
                Box::pin(async move {
                    self.calls.fetch_add(1, Ordering::SeqCst);
                    if self.fail.load(Ordering::SeqCst) {
                        return Err(crate::managed_run::RunError::Unknown);
                    }
                    assert_eq!(plan.binding, self.admission.binding);
                    assert_eq!(plan.recovery.consumed_ref, self.admission.consumed_ref);
                    if self.not_ready_once.swap(false, Ordering::SeqCst) {
                        return Err(crate::managed_run::RunError::NotReady);
                    }
                    self.entered.notify_one();
                    self.release.notified().await;
                    Ok(self.admission.clone())
                })
            }
            fn consensus<'a>(
                &'a self,
                pending: crate::managed_state::PendingConsensus,
                _store: &'a SharedStore,
                _lease: &'a ManagedLease,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<
                            Output = Result<crate::managed_state::ConsensusFence, Fault>,
                        > + Send
                        + 'a,
                >,
            > {
                Box::pin(async move { pending.verify(&self.run) })
            }
        }

        let (_directory, mut initial, binding, incarnation, run) = fixture();
        let db = initial.test_db();
        index_managed_member(db, &binding);
        let raw: String =
            db.query_row("SELECT data FROM members WHERE id='member'", [], |row| {
                row.get(0)
            })?;
        let mut member: Binding = serde_json::from_str(&raw)?;
        member.member.state = crate::domain::MemberState::Active;
        db.execute(
            "UPDATE members SET data=?1 WHERE id='member'",
            [serde_json::to_string(&member)?],
        )?;
        let command = Command::Post(crate::domain::Message {
            change: crate::domain::Change {
                pool_id: "pool".into(),
                expected_revision: 1,
                request_key: "shared-key".into(),
            },
            body: "only once".into(),
        });
        let digest1 = prepare_command(
            db,
            &run,
            &binding,
            &incarnation,
            "context-1",
            "intent-1",
            "inv-1",
            &command,
        );
        let digest2 = prepare_command(
            db,
            &run,
            &binding,
            &incarnation,
            "context-2",
            "intent-2",
            "inv-2",
            &command,
        );
        let authority1 = fresh_authority(db, &binding, "context-1", "inv-1")?;
        let authority2 = fresh_authority(db, &binding, "context-2", "inv-2")?;
        let synthetic1 = fake_consumed(
            &binding,
            &incarnation,
            "intent-1",
            "inv-1",
            &digest1,
            &command,
        );
        let synthetic2 = fake_consumed(
            &binding,
            &incarnation,
            "intent-2",
            "inv-2",
            &digest2,
            &command,
        );
        let bridge = FakeBridge {
            receipts: [
                ("intent-1".into(), synthetic1),
                ("intent-2".into(), synthetic2),
            ]
            .into_iter()
            .collect(),
        };
        let consume = |intent: &str, invocation: &str, digest: &str| {
            let key = crate::managed_bridge::ConsumeKey {
                abort_request_id: "unused",
                expected_store_id: &binding.bridge_route.component_store_id,
                producer: "pool",
                consume_request_id: intent,
                invocation_key: invocation,
                security_digest: digest,
                audience: "pool",
            };
            crate::managed_bridge::consume_original(
                &bridge,
                &key,
                &bridge_sdk::bridge_protocol::Secret::new("fixture-only"),
                "pool",
                &command,
                "epoch",
            )
            .map_err(|_| Fault::Unauthorized)
        };
        let consumed1 = consume("intent-1", "inv-1", &digest1)?;
        let consumed2 = consume("intent-2", "inv-2", &digest2)?;
        let admission = consumed_admission(
            db,
            &run,
            &binding,
            &incarnation,
            "intent-1",
            "inv-1",
            &digest1,
            &command,
        );
        let route = crate::managed_state::Route {
            component_store_id: binding.pool_store_id.clone(),
            route_id: "pool-route".into(),
            worker_uid: binding.run_route.worker_uid,
        };
        let first = managed_dispatch::Mutation {
            bootstrap_id: "context-1".into(),
            context_id: "context-1".into(),
            intent_id: "intent-1".into(),
            member_id: "member".into(),
            command: command.clone(),
            digest: digest1,
            authority: authority1,
            consumed: consumed1,
            pool_route: route.clone(),
        };
        let second_digest = digest2.clone();
        let second = managed_dispatch::Mutation {
            bootstrap_id: "context-2".into(),
            context_id: "context-2".into(),
            intent_id: "intent-2".into(),
            member_id: "member".into(),
            command,
            digest: digest2,
            authority: authority2,
            consumed: consumed2,
            pool_route: route,
        };
        let client = Arc::new(FakeClient {
            admission,
            run,
            calls: AtomicUsize::new(0),
            fail: AtomicBool::new(false),
            not_ready_once: AtomicBool::new(true),
            entered: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        });
        let store = Arc::new(Mutex::new(initial));
        let activity = Arc::new(ManagedActivity::default());
        let first_lease = activity
            .acquire(ManagedWork::Bootstrap("context-1".into()))?
            .ok_or("first lease")?;
        let second_lease = activity
            .acquire(ManagedWork::Bootstrap("context-2".into()))?
            .ok_or("second lease")?;
        let first_store = Arc::clone(&store);
        let first_activity = Arc::clone(&activity);
        let first_client = Arc::clone(&client);
        let task = tokio::spawn(async move {
            managed_dispatch::mutation(
                &first_store,
                &first_activity,
                &first_lease,
                first,
                first_client.as_ref(),
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(30), client.entered.notified()).await?;
        assert_eq!(
            managed_dispatch::mutation(&store, &activity, &second_lease, second, client.as_ref())
                .await?,
            crate::managed_state::IntentReservation::Pending
        );
        let action = stored_managed(&store, &second_lease, |store| {
            store.managed_stage_bootstrap("context-2")
        })
        .await?;
        let crate::managed_state::BootstrapRecoveryAction::BridgeAbort {
            context_id,
            pin,
            key,
        } = action
        else {
            return Err("losing invocation did not retain Bridge recovery".into());
        };
        assert_eq!(key.security_digest, second_digest);
        assert_eq!(key.consume_request_id, "intent-2");
        let abort = crate::managed_bridge::abort_original(&bridge, &key.borrowed())
            .map_err(|_| "fake Bridge abort")?;
        stored_managed(&store, &second_lease, move |store| {
            store.managed_record_bootstrap_abort(&context_id, &key, &pin, &abort)
        })
        .await?;
        client.release.notify_one();
        let first_result = task.await??;
        let crate::managed_state::IntentReservation::Committed(receipt) = first_result else {
            return Err("expected committed receipt".into());
        };
        let reply: Reply = serde_json::from_str(&receipt)?;
        let Reply::Receipt(reply) = reply else {
            return Err("expected mutation receipt".into());
        };
        assert_eq!(reply.revision, 2);
        assert_eq!(reply.event.body, "only once");
        assert_eq!(client.calls.load(Ordering::SeqCst), 2);
        let event_count = stored(&store, |store| {
            Ok(store
                .test_db()
                .query_row("SELECT count(*) FROM events", [], |row| {
                    row.get::<_, i64>(0)
                })?)
        })
        .await?;
        assert_eq!(event_count, 1);

        // An uncertain Run result leaves a durable local abort and retains its
        // domain key until both original remote fences are recovered.
        client.fail.store(true, Ordering::SeqCst);
        let retry_command = Command::Post(crate::domain::Message {
            change: crate::domain::Change {
                pool_id: "pool".into(),
                expected_revision: 2,
                request_key: "next-key".into(),
            },
            body: "not committed".into(),
        });
        let next_client = Arc::clone(&client);
        let next_binding = binding.clone();
        let next_incarnation = incarnation.clone();
        let next_command = retry_command.clone();
        let (next_digest, next_authority, next_consumed) = stored(&store, move |store| {
            let db = store.test_db();
            let digest = prepare_command(
                db,
                &next_client.run,
                &next_binding,
                &next_incarnation,
                "context-3",
                "intent-3",
                "inv-3",
                &next_command,
            );
            let authority = fresh_authority(db, &next_binding, "context-3", "inv-3")?;
            let consumed = fake_consumed(
                &next_binding,
                &next_incarnation,
                "intent-3",
                "inv-3",
                &digest,
                &next_command,
            );
            Ok((digest, authority, consumed))
        })
        .await?;
        let next_lease = activity
            .acquire(ManagedWork::Bootstrap("context-3".into()))?
            .ok_or("third lease")?;
        let next = managed_dispatch::Mutation {
            bootstrap_id: "context-3".into(),
            context_id: "context-3".into(),
            intent_id: "intent-3".into(),
            member_id: "member".into(),
            command: retry_command,
            digest: next_digest,
            authority: next_authority,
            consumed: next_consumed,
            pool_route: crate::managed_state::Route {
                component_store_id: binding.pool_store_id.clone(),
                route_id: "pool-route".into(),
                worker_uid: binding.run_route.worker_uid,
            },
        };
        assert_eq!(
            managed_dispatch::mutation(&store, &activity, &next_lease, next, client.as_ref())
                .await
                .err(),
            Some(Fault::Unavailable)
        );
        let terminal = stored(&store, |store| {
            Ok(store.test_db().query_row(
                "SELECT state,effect_free,bridge_resolved,run_resolved,(SELECT count(*) FROM managed_domain_keys WHERE intent_id='intent-3') FROM managed_intents WHERE id='intent-3'",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?, row.get::<_, i64>(3)?, row.get::<_, i64>(4)?)),
            )?)
        }).await?;
        assert_eq!(terminal, ("aborted".into(), 1, 0, 0, 1));
        assert_eq!(client.calls.load(Ordering::SeqCst), 3);

        struct FakeVote<'a> {
            admission: crate::managed_run::Admission,
            run: &'a FakeRun,
        }
        impl managed_dispatch::Client for FakeVote<'_> {
            fn admit<'a>(
                &'a self,
                plan: &'a crate::managed_state::AdmissionPlan,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<
                            Output = Result<
                                crate::managed_run::Admission,
                                crate::managed_run::RunError,
                            >,
                        > + Send
                        + 'a,
                >,
            > {
                Box::pin(async move {
                    assert_eq!(plan.binding, self.admission.binding);
                    Ok(self.admission.clone())
                })
            }
            fn consensus<'a>(
                &'a self,
                pending: crate::managed_state::PendingConsensus,
                _store: &'a SharedStore,
                _lease: &'a ManagedLease,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<
                            Output = Result<crate::managed_state::ConsensusFence, Fault>,
                        > + Send
                        + 'a,
                >,
            > {
                Box::pin(async move { pending.verify(self.run) })
            }
        }
        let vote_client = Arc::clone(&client);
        let vote_binding = binding.clone();
        let vote_incarnation = incarnation.clone();
        let (vote_command, vote_digest, vote_authority, vote_consumed, vote_admission) =
            stored(&store, move |store| {
                let db = store.test_db();
                let raw: String =
                    db.query_row("SELECT data FROM pools WHERE id='pool'", [], |row| {
                        row.get(0)
                    })?;
                let mut pool: crate::domain::Pool =
                    serde_json::from_str(&raw).map_err(|_| Fault::Internal)?;
                pool.proposal = Some(crate::domain::Proposal {
                    proposal_id: "proposal".into(),
                    roster_key: "roster".into(),
                    voters: vec!["member".into()],
                    result: "result".into(),
                    criteria: "criteria".into(),
                    snapshot: None,
                    snapshot_bytes: None,
                    state: crate::domain::ProposalState::Open,
                    votes: std::collections::BTreeMap::new(),
                });
                let proposal =
                    serde_json::to_string(pool.proposal.as_ref().ok_or(Fault::Internal)?)
                        .map_err(|_| Fault::Internal)?;
                db.execute(
                    "INSERT INTO proposals(id,pool,state,data) VALUES('proposal','pool','open',?1)",
                    [proposal],
                )?;
                db.execute(
                    "UPDATE pools SET data=?1 WHERE id='pool'",
                    [serde_json::to_string(&pool).map_err(|_| Fault::Internal)?],
                )?;
                let vote = Command::Vote(crate::domain::Vote {
                    change: crate::domain::Change {
                        pool_id: "pool".into(),
                        expected_revision: 2,
                        request_key: "vote-key".into(),
                    },
                    proposal_id: "proposal".into(),
                    roster_key: "roster".into(),
                    choice: crate::domain::Choice::Ready,
                    evidence: "verified".into(),
                    checks: vec![],
                });
                let digest = prepare_command(
                    db,
                    &vote_client.run,
                    &vote_binding,
                    &vote_incarnation,
                    "vote-context",
                    "vote-intent",
                    "vote-inv",
                    &vote,
                );
                let authority = fresh_authority(db, &vote_binding, "vote-context", "vote-inv")?;
                let consumed = fake_consumed(
                    &vote_binding,
                    &vote_incarnation,
                    "vote-intent",
                    "vote-inv",
                    &digest,
                    &vote,
                );
                let admission = consumed_admission(
                    db,
                    &vote_client.run,
                    &vote_binding,
                    &vote_incarnation,
                    "vote-intent",
                    "vote-inv",
                    &digest,
                    &vote,
                );
                Ok((vote, digest, authority, consumed, admission))
            })
            .await?;
        let vote_lease = activity
            .acquire(ManagedWork::Bootstrap("vote-context".into()))?
            .ok_or("vote lease")?;
        let vote_request = managed_dispatch::Mutation {
            bootstrap_id: "vote-context".into(),
            context_id: "vote-context".into(),
            intent_id: "vote-intent".into(),
            member_id: "member".into(),
            command: vote_command,
            digest: vote_digest,
            authority: vote_authority,
            consumed: vote_consumed,
            pool_route: crate::managed_state::Route {
                component_store_id: binding.pool_store_id.clone(),
                route_id: "pool-route".into(),
                worker_uid: binding.run_route.worker_uid,
            },
        };
        let vote_result = managed_dispatch::mutation(
            &store,
            &activity,
            &vote_lease,
            vote_request,
            &FakeVote {
                admission: vote_admission,
                run: &client.run,
            },
        )
        .await?;
        let crate::managed_state::IntentReservation::Committed(vote_receipt) = vote_result else {
            return Err("expected committed vote".into());
        };
        let reply: Reply = serde_json::from_str(&vote_receipt)?;
        let Reply::Receipt(reply) = reply else {
            return Err("expected vote receipt".into());
        };
        assert_eq!(reply.event.kind, "proposal_accepted");
        let verified = stored(&store, |store| {
            Ok(store.test_db().query_row(
                "SELECT count(*) FROM managed_ballot_provenance",
                [],
                |row| row.get::<_, i64>(0),
            )?)
        })
        .await?;
        assert_eq!(verified, 1);

        struct CancelClient {
            entered: tokio::sync::Notify,
        }
        impl managed_dispatch::Client for CancelClient {
            fn admit<'a>(
                &'a self,
                _plan: &'a crate::managed_state::AdmissionPlan,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<
                            Output = Result<
                                crate::managed_run::Admission,
                                crate::managed_run::RunError,
                            >,
                        > + Send
                        + 'a,
                >,
            > {
                Box::pin(async move {
                    self.entered.notify_one();
                    std::future::pending().await
                })
            }
            fn consensus<'a>(
                &'a self,
                _pending: crate::managed_state::PendingConsensus,
                _store: &'a SharedStore,
                _lease: &'a ManagedLease,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<
                            Output = Result<crate::managed_state::ConsensusFence, Fault>,
                        > + Send
                        + 'a,
                >,
            > {
                Box::pin(async { Err(Fault::Unavailable) })
            }
        }
        let cancel_command = Command::Post(crate::domain::Message {
            change: crate::domain::Change {
                pool_id: "pool".into(),
                expected_revision: 3,
                request_key: "cancel-key".into(),
            },
            body: "never committed".into(),
        });
        let cancel_client = Arc::clone(&client);
        let cancel_binding = binding.clone();
        let cancel_incarnation = incarnation.clone();
        let staged_command = cancel_command.clone();
        let (cancel_digest, cancel_authority, cancel_consumed) = stored(&store, move |store| {
            let db = store.test_db();
            let digest = prepare_command(
                db,
                &cancel_client.run,
                &cancel_binding,
                &cancel_incarnation,
                "cancel-context",
                "cancel-intent",
                "cancel-inv",
                &staged_command,
            );
            let authority = fresh_authority(db, &cancel_binding, "cancel-context", "cancel-inv")?;
            let consumed = fake_consumed(
                &cancel_binding,
                &cancel_incarnation,
                "cancel-intent",
                "cancel-inv",
                &digest,
                &staged_command,
            );
            Ok((digest, authority, consumed))
        })
        .await?;
        let cancel_lease = activity
            .acquire(ManagedWork::Bootstrap("cancel-context".into()))?
            .ok_or("cancel lease")?;
        let request = managed_dispatch::Mutation {
            bootstrap_id: "cancel-context".into(),
            context_id: "cancel-context".into(),
            intent_id: "cancel-intent".into(),
            member_id: "member".into(),
            command: cancel_command,
            digest: cancel_digest.clone(),
            authority: cancel_authority,
            consumed: cancel_consumed,
            pool_route: crate::managed_state::Route {
                component_store_id: binding.pool_store_id.clone(),
                route_id: "pool-route".into(),
                worker_uid: binding.run_route.worker_uid,
            },
        };
        let cancel_run = Arc::new(CancelClient {
            entered: tokio::sync::Notify::new(),
        });
        let task_store = Arc::clone(&store);
        let task_activity = Arc::clone(&activity);
        let task_run = Arc::clone(&cancel_run);
        let task = tokio::spawn(async move {
            managed_dispatch::mutation(
                &task_store,
                &task_activity,
                &cancel_lease,
                request,
                task_run.as_ref(),
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(30), cancel_run.entered.notified()).await?;
        task.abort();
        let _ = task.await;
        let recovery = activity
            .acquire(ManagedWork::Intent("cancel-intent".into()))?
            .ok_or("cancelled intent lease leaked")?;
        let action = stored_managed(&store, &recovery, move |store| {
            store.managed_stage_recovery("cancel-intent", &cancel_digest)
        })
        .await?;
        assert!(matches!(
            action,
            crate::managed_state::RecoveryAction::LocallyFenced
        ));
        let state = stored(&store, |store| {
            Ok(store.test_db().query_row(
                "SELECT state FROM managed_intents WHERE id='cancel-intent'",
                [],
                |row| row.get::<_, String>(0),
            )?)
        })
        .await?;
        assert_eq!(state, "aborted");
        Ok(())
    }

    /// A cancelled caller cannot release its lease while its blocking store work is still running.
    #[tokio::test]
    async fn managed_lease_survives_cancelled_store_caller()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory =
            tempfile::tempdir_in(std::env::var_os("TMPDIR").ok_or("task TMPDIR required")?)?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let store = Arc::new(Mutex::new(Store::open(&directory.path().join("pool.db"))?));
        let activity = Arc::new(ManagedActivity::default());
        let key = ManagedWork::Intent("intent".into());
        let lease = activity
            .acquire(key.clone())?
            .ok_or("intent already active")?;
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        let task_store = Arc::clone(&store);
        let task_lease = lease.clone();
        let task = tokio::spawn(async move {
            stored_managed(&task_store, &task_lease, move |_| {
                let _ = started_tx.send(());
                release_rx.recv().map_err(|_| Fault::Internal)?;
                Ok(())
            })
            .await
        });
        tokio::time::timeout(Duration::from_secs(30), started_rx).await??;
        task.abort();
        let _ = task.await;
        drop(lease);
        assert!(activity.acquire(key.clone())?.is_none());
        release_tx.send(())?;
        let wait_store = Arc::clone(&store);
        tokio::task::spawn_blocking(move || {
            let _store = wait_store.lock().map_err(|_| Fault::Internal)?;
            Ok::<_, Fault>(())
        })
        .await??;
        assert!(activity.acquire(key)?.is_some());
        Ok(())
    }

    /// Recovery locally fences an unregistered prepare without contacting Bridge or Run.
    #[tokio::test]
    async fn managed_recovery_abandons_unregistered_without_bridge_io()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory =
            tempfile::tempdir_in(std::env::var_os("TMPDIR").ok_or("task TMPDIR required")?)?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let path = directory.path();
        let uid = fs::metadata(path)?.uid();
        let config = Config {
            socket_path: path.join("pool.sock"),
            database_path: path.join("pool.db"),
            expected_uid: uid,
            bridge_registration_socket: path.join("absent-adapter.sock"),
            bridge_core_socket: path.join("absent-core.sock"),
            bridge_credential_file: path.join("absent-token"),
            bridge_producer_id: "pool".into(),
            bridge_audience: "pool".into(),
            bridge_server_executable: path.join("absent-bridge"),
            bridge_server_sha256: "a".repeat(64),
            bridge_observer_socket: None,
            bridge_observer_credential_file: None,
            owner_observer_credential_file: None,
            run_socket: None,
            run_peer_uid: None,
            managed_run_reader: None,
            managed_run_transport: None,
        };
        let mut initial = Store::open(&config.database_path)?;
        let route = crate::managed_state::Route {
            component_store_id: "00000000-0000-4000-8000-000000000001".into(),
            route_id: "bridge-route".into(),
            worker_uid: uid,
        };
        let pin = crate::managed_bridge::BridgePin {
            route: route.clone(),
            producer: "pool".into(),
            registration_socket: config.bridge_registration_socket.clone(),
            core_socket: config.bridge_core_socket.clone(),
            server_executable: config.bridge_server_executable.clone(),
            server_sha256: config.bridge_server_sha256.clone(),
            credential_file: config.bridge_credential_file.clone(),
            credential_sha256: "b".repeat(64),
        };
        let command = Command::List(crate::domain::List { after: None });
        let proof = bridge_sdk::bridge_protocol::CallEvidence::Native {
            host: bridge_sdk::bridge_protocol::Host::Codex,
            metadata: serde_json::Map::new(),
        };
        crate::managed_state::persist_bridge_route(initial.test_db(), &pin)?;
        crate::managed_state::reserve_bootstrap(
            initial.test_db(),
            &crate::managed_state::BootstrapRequest {
                namespace_id: "ns",
                bootstrap_id: "bootstrap",
                route: &route,
                bridge_pin: &pin,
                producer: "pool",
                issuer_epoch: "opaque-epoch",
                invocation_key: "inv",
                command: &command,
                native_proof: &proof,
            },
        )?;
        drop(crate::managed_state::mark_bootstrap_submitted(
            initial.test_db(),
            "bootstrap",
        )?);
        let store = Arc::new(Mutex::new(initial));
        let (_stop, stopped) = watch::channel(false);
        let activity = Arc::new(ManagedActivity::default());
        let lease = activity
            .acquire(ManagedWork::Bootstrap("bootstrap".into()))?
            .ok_or("bootstrap already active")?;
        let held = lease.clone();
        drop(lease);
        recover_managed(&config, &store, &stopped, &activity).await?;
        let active_state = stored(&store, |store| {
            Ok(store.test_db().query_row(
                "SELECT state FROM managed_bootstrap WHERE id='bootstrap'",
                [],
                |row| row.get::<_, String>(0),
            )?)
        })
        .await?;
        assert_eq!(active_state, "submitted");
        drop(held);
        // The bounded cursor wraps after skipping the occupied entry.
        recover_managed(&config, &store, &stopped, &activity).await?;
        recover_managed(&config, &store, &stopped, &activity).await?;
        let state = stored(&store, |store| {
            let row: (String, Option<String>) = store.test_db().query_row(
                "SELECT state,abort_receipt FROM managed_bootstrap WHERE id='bootstrap'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            Ok(row)
        })
        .await?;
        assert_eq!(state, ("terminal".into(), None));
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
            bridge_server_executable: "/fixture/bridge".into(),
            bridge_server_sha256: "0".repeat(64),
            bridge_observer_socket: None,
            bridge_observer_credential_file: None,
            owner_observer_credential_file: Some(token),
            run_socket: Some(path.join("run.sock")),
            run_peer_uid: None,
            managed_run_reader: None,
            managed_run_transport: None,
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
            bridge_server_executable: "/fixture/bridge".into(),
            bridge_server_sha256: "0".repeat(64),
            bridge_observer_socket: None,
            bridge_observer_credential_file: None,
            owner_observer_credential_file: None,
            run_socket: None,
            run_peer_uid: None,
            managed_run_reader: None,
            managed_run_transport: None,
        };
        let (stop, stopped) = watch::channel(false);
        stop.send(true)?;
        let mut worker = tokio::spawn(work(
            config,
            Arc::clone(&store),
            stopped,
            Arc::new(ManagedActivity::default()),
        ));
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
