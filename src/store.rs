//! Single-writer SQLite state machine. Transactions commit business state and delivery intents together.
use crate::domain::*;
use fs2::FileExt;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    time::Duration,
};

/// Resident-owned connection and exclusive lifetime lease; never held across network operations.
pub struct Store {
    /// SQLite connection; callers serialize access with the resident's short-lived mutex.
    db: Connection,
    /// Exclusive lock remains open until the resident releases the store.
    _lease: File,
    /// Round-robin reconciliation cursor, preventing a permanently unknown head from starving later work.
    unknown_cursor: i64,
}
impl Store {
    /// Opens one private database, takes a nonblocking exclusive writer lease and migrates schema v1.
    /// The existing parent must be a real 0700 directory; future schemas and second writers refuse.
    pub fn open(path: &Path) -> Result<Self, Fault> {
        let parent = path.parent().ok_or(Fault::Invalid)?;
        let meta = std::fs::symlink_metadata(parent).map_err(|_| Fault::Unavailable)?;
        if !meta.is_dir() || meta.permissions().mode() & 0o777 != 0o700 {
            return Err(Fault::Forbidden);
        }
        for p in [path.to_path_buf(), path.with_extension("lock")] {
            if std::fs::symlink_metadata(&p)
                .is_ok_and(|m| !m.is_file() || m.permissions().mode() & 0o077 != 0)
            {
                return Err(Fault::Forbidden);
            }
        }
        let lease = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(path.with_extension("lock"))
            .map_err(|_| Fault::Unavailable)?;
        lease.try_lock_exclusive().map_err(|_| Fault::Conflict)?;
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .map_err(|_| Fault::Unavailable)?;
        drop(file);
        let db = Connection::open(path)?;
        db.busy_timeout(Duration::from_secs(2))?;
        let version: i64 = db.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version > 1 {
            return Err(Fault::Conflict);
        }
        db.execute_batch(
            "PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;",
        )?;
        if version == 0 {
            db.execute_batch("BEGIN IMMEDIATE;
CREATE TABLE leaders(actor TEXT PRIMARY KEY,address TEXT NOT NULL UNIQUE);
CREATE TABLE pools(id TEXT PRIMARY KEY,owner TEXT NOT NULL REFERENCES leaders(actor),data TEXT NOT NULL);
CREATE TABLE proposals(id TEXT PRIMARY KEY,pool TEXT NOT NULL REFERENCES pools(id),state TEXT NOT NULL,data TEXT NOT NULL);
CREATE TABLE members(id TEXT PRIMARY KEY,pool TEXT NOT NULL REFERENCES pools(id),actor TEXT,address TEXT,current INTEGER NOT NULL,data TEXT NOT NULL);
CREATE UNIQUE INDEX member_actor_current ON members(actor) WHERE current=1 AND actor IS NOT NULL;
CREATE UNIQUE INDEX member_address_current ON members(address) WHERE current=1 AND address IS NOT NULL;
CREATE INDEX member_pool ON members(pool,current);
CREATE TABLE requests(scope TEXT NOT NULL,key TEXT NOT NULL,digest TEXT NOT NULL,receipt TEXT NOT NULL,PRIMARY KEY(scope,key));
CREATE TABLE events(id INTEGER PRIMARY KEY AUTOINCREMENT,pool TEXT NOT NULL REFERENCES pools(id),data TEXT NOT NULL);
CREATE INDEX event_pool ON events(pool,id);
CREATE TABLE effects(sequence INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT NOT NULL UNIQUE,pool TEXT NOT NULL REFERENCES pools(id),member TEXT,state TEXT NOT NULL,data TEXT NOT NULL,failure_notice INTEGER NOT NULL DEFAULT 0);
CREATE INDEX effect_state ON effects(state,sequence);
CREATE TABLE publications(effect TEXT PRIMARY KEY REFERENCES effects(id),producer TEXT NOT NULL,params TEXT NOT NULL);
CREATE TABLE alerts(effect TEXT NOT NULL REFERENCES effects(id),kind TEXT NOT NULL,PRIMARY KEY(effect,kind));
PRAGMA user_version=1; COMMIT;")?;
        }
        // A crash may have happened after a provider accepted the work. Never turn these back into queued.
        db.execute(
            "UPDATE effects SET state='unknown' WHERE state='inflight'",
            [],
        )?;
        Ok(Self {
            db,
            _lease: lease,
            unknown_cursor: 0,
        })
    }
    /// Authenticates current membership before replay lookup, then executes a non-join command.
    /// Joins must use execute_join with the provider-prevalidated binding; no unfenced join path exists.
    /// Errors roll back all local changes. External I/O belongs exclusively to the outbox worker.
    pub fn execute(&mut self, actor: &Actor, command: &Command) -> Result<Reply, Fault> {
        command.validate()?;
        if matches!(command, Command::Join(_)) {
            return Err(Fault::Invalid);
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let reply = execute(&tx, actor, command)?;
        tx.commit()?;
        Ok(reply)
    }
    /// Executes a join only against the exact incarnation prevalidated outside provider I/O.
    /// The binding fence and authorization/replay run in one write transaction; any changed
    /// assignment, native tuple or removal refuses even if the caller supplied a newer revision.
    pub fn execute_join(
        &mut self,
        actor: &Actor,
        command: &Command,
        expected: &Binding,
    ) -> Result<Reply, Fault> {
        command.validate()?;
        if !matches!(command,Command::Join(change) if change.pool_id==expected.pool_id) {
            return Err(Fault::Invalid);
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (current, active) = binding_any(&tx, &expected.member.member_id)?;
        if !active || current != *expected {
            return Err(Fault::Stale);
        }
        let reply = execute(&tx, actor, command)?;
        tx.commit()?;
        Ok(reply)
    }
    /// Reads the exact current incarnation eligible for this authenticated caller's join precheck.
    /// Absence refuses; execute_join rechecks equality transactionally after provider I/O.
    pub fn join_binding(&self, actor: &Actor, pool_id: &str) -> Result<Binding, Fault> {
        bindings(&self.db, pool_id)?
            .into_iter()
            .find(|b| {
                b.actor.as_deref() == Some(&actor.key)
                    || (b.actor.is_none() && b.address.as_deref() == Some(&actor.address))
            })
            .ok_or(Fault::Forbidden)
    }
    /// Claims the oldest queued intent, persisting inflight before the worker can contact a provider.
    pub fn next_effect(&mut self) -> Result<Option<Effect>, Fault> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row: Option<String> = tx
            .query_row(
                "SELECT data FROM effects WHERE state='queued' ORDER BY sequence LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        let Some(row) = row else { return Ok(None) };
        let mut effect: Effect = decode(&row)?;
        effect.state = "inflight".into();
        tx.execute(
            "UPDATE effects SET state='inflight',data=?2 WHERE id=?1 AND state='queued'",
            params![effect.effect_id, encode(&effect)?],
        )?;
        tx.commit()?;
        Ok(Some(effect))
    }
    /// Returns at most 32 uncertain effects for status reconciliation, never automatic new IDs.
    pub fn pending_unknown(&mut self) -> Result<Vec<Effect>, Fault> {
        let mut stmt=self.db.prepare("SELECT sequence,data,state FROM effects WHERE state IN ('unknown','custody') AND sequence>?1 ORDER BY sequence LIMIT 32")?;
        let rows = stmt.query_map([self.unknown_cursor], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (sequence, data, state) = row?;
            let mut e: Effect = decode(&data)?;
            e.state = state;
            out.push(e);
            self.unknown_cursor = sequence;
        }
        if out.len() < 32 {
            self.unknown_cursor = 0;
        }
        Ok(out)
    }
    /// Returns the retained exact membership of an effect, including removal and immediate Run receipt.
    /// This private view lets reconciliation inspect admitted work without starting a removed agent.
    pub fn effect_binding(&self, effect_id: &str) -> Result<Option<(Binding, bool)>, Fault> {
        let e = effect(&self.db, effect_id)?;
        e.member_id
            .as_deref()
            .map(|mid| binding_any(&self.db, mid))
            .transpose()
    }
    /// Freezes the producer association and exact provider publication before the first write.
    /// Every retry must match the persisted semantic parameters; a changed config cannot redirect work.
    pub fn freeze_publication(
        &mut self,
        effect_id: &str,
        producer: &str,
        params: &serde_json::Value,
    ) -> Result<(String, serde_json::Value), Fault> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let e = effect(&tx, effect_id)?;
        if !matches!(e.work, Work::Deliver { .. }) || producer.is_empty() || !params.is_object() {
            return Err(Fault::Invalid);
        }
        let prior: Option<(String, String)> = tx
            .query_row(
                "SELECT producer,params FROM publications WHERE effect=?1",
                [effect_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((p, s)) = prior {
            let value: serde_json::Value = decode(&s)?;
            if p != producer || value != *params {
                return Err(Fault::Conflict);
            }
            return Ok((p, value));
        }
        tx.execute(
            "INSERT INTO publications(effect,producer,params) VALUES(?1,?2,?3)",
            params![effect_id, producer, encode(params)?],
        )?;
        tx.commit()?;
        Ok((producer.into(), params.clone()))
    }
    /// Records only a closed delivery outcome; uncertain work cannot silently be requeued.
    pub fn settle_effect(&mut self, effect_id: &str, state: &str) -> Result<(), Fault> {
        if !["unknown", "custody", "accepted", "refused", "cancelled"].contains(&state) {
            return Err(Fault::Invalid);
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut effect = effect(&tx, effect_id)?;
        if ["accepted", "refused", "cancelled"].contains(&effect.state.as_str()) {
            return if effect.state == state {
                Ok(())
            } else {
                Err(Fault::Conflict)
            };
        }
        effect.state = state.into();
        tx.execute(
            "UPDATE effects SET state=?2,data=?3 WHERE id=?1",
            params![effect_id, state, encode(&effect)?],
        )?;
        if matches!(state, "refused" | "cancelled") && matches!(effect.work, Work::Start { .. }) {
            let (binding, _) =
                binding_any(&tx, effect.member_id.as_deref().ok_or(Fault::Internal)?)?;
            if binding.run_id.is_none() && binding.address.is_none() {
                // A positively unadmitted start has no native agent to notify. Preserve
                // uncertain starts instead; this branch never handles outcome_unknown.
                tx.execute("UPDATE effects SET state='cancelled' WHERE member=?1 AND state='awaiting_binding'",[&binding.member.member_id])?;
            }
        }
        let failure_notice: bool = tx.query_row(
            "SELECT failure_notice FROM effects WHERE id=?1",
            [effect_id],
            |r| r.get(0),
        )?;
        if !failure_notice
            && matches!(state, "refused" | "unknown")
            && !matches!(effect.work, Work::Retire { .. })
        {
            let inserted = tx.execute(
                "INSERT OR IGNORE INTO alerts(effect,kind) VALUES(?1,?2)",
                params![effect_id, state],
            )?;
            if inserted > 0 {
                failure_event(
                    &tx,
                    &effect.pool_id,
                    effect.member_id.as_deref(),
                    if state == "unknown" {
                        "Delivery or admission outcome unknown; reconciliation required."
                    } else {
                        "Delivery or admission refused; owner intervention required."
                    },
                )?;
            }
        }
        tx.commit()?;
        Ok(())
    }
    /// Persists a successful Run admission immediately, even when its native binding is not ready.
    /// Repeated identical admission is harmless; differing agent or sequence is refused.
    pub fn record_run_admission(
        &mut self,
        effect_id: &str,
        agent_id: &str,
        sequence: u64,
    ) -> Result<(), Fault> {
        if agent_id.is_empty() || sequence == 0 {
            return Err(Fault::Invalid);
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let e = effect(&tx, effect_id)?;
        if !matches!(e.work, Work::Start { .. }) {
            return Err(Fault::Invalid);
        }
        let mid = e.member_id.as_deref().ok_or(Fault::Internal)?;
        let (mut b, current) = binding_any(&tx, mid)?;
        if b.run_id.as_deref().is_some_and(|v| v != agent_id)
            || b.run_sequence.is_some_and(|v| v != sequence)
        {
            return Err(Fault::Conflict);
        }
        b.run_id = Some(agent_id.into());
        b.run_sequence = Some(sequence);
        save_binding(&tx, &b, current)?;
        // Admission is known; custody remains monitored until native binding or a final removal notice.
        tx.execute("UPDATE effects SET state='custody' WHERE id=?1 AND state NOT IN ('accepted','refused','cancelled')",[effect_id])?;
        tx.commit()?;
        Ok(())
    }
    /// Binds a Run admission to one canonical native destination after the Run observer verifies it.
    /// Global leader and current membership reservations are rechecked; removed members stay removed.
    pub fn bind_run(&mut self, effect_id: &str, address: &str) -> Result<(), Fault> {
        text(address, 1024)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let e = effect(&tx, effect_id)?;
        let (mut b, current) = binding_any(&tx, e.member_id.as_deref().ok_or(Fault::Internal)?)?;
        if b.run_id.is_none() {
            return Err(Fault::Conflict);
        }
        if b.address.as_deref().is_some_and(|v| v != address) {
            return Err(Fault::Conflict);
        }
        if current {
            reserve(&tx, address, Some(&b.member.member_id))?;
        }
        if b.address.is_none() {
            b.address = Some(address.into());
            save_binding(&tx, &b, current)?;
            let (pool, _) = pool(&tx, &b.pool_id)?;
            let members = bindings(&tx, &b.pool_id)?;
            if current {
                queue_delivery(
                    &tx,
                    &pool.pool_id,
                    Some(&b.member.member_id),
                    address,
                    &scope(&b.member.member_id),
                    onboarding(&pool, &members, &b.member)?,
                )?;
            }
            let mut stmt=tx.prepare("SELECT id,data FROM effects WHERE member=?1 AND state='awaiting_binding' ORDER BY sequence")?;
            let rows = stmt
                .query_map([&b.member.member_id], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            drop(stmt);
            for (eid, data) in rows {
                let mut waiting: Effect = decode(&data)?;
                let Work::Deliver {
                    address: destination,
                    ..
                } = &mut waiting.work
                else {
                    return Err(Fault::Internal);
                };
                if !destination.is_empty() {
                    return Err(Fault::Conflict);
                }
                *destination = address.into();
                waiting.state = "queued".into();
                tx.execute(
                    "UPDATE effects SET state='queued',data=?2 WHERE id=?1",
                    params![eid, encode(&waiting)?],
                )?;
            }
        }
        tx.execute(
            "UPDATE effects SET state='accepted' WHERE id=?1",
            [effect_id],
        )?;
        tx.commit()?;
        Ok(())
    }
    /// Returns current private observation targets, bounded by configured roster limits per pool.
    pub fn observation_targets(&self) -> Result<Vec<Binding>, Fault> {
        let mut stmt = self
            .db
            .prepare("SELECT data FROM members WHERE current=1 ORDER BY id")?;
        stmt.query_map([], |r| r.get::<_, String>(0))?
            .map(|r| decode(&r?))
            .collect()
    }
    /// Records changed supported execution observations; unknown never means ended.
    /// Failures also notify the owner separately, without subscribing them to member conversations.
    pub fn observe_member(
        &mut self,
        pool_id: &str,
        member_id: &str,
        runtime: &str,
    ) -> Result<(), Fault> {
        if ![
            "active",
            "inactive",
            "awaiting_input",
            "unknown",
            "succeeded",
            "failed",
            "lost",
            "cancelled",
        ]
        .contains(&runtime)
        {
            return Err(Fault::Invalid);
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (mut b, current) = binding_any(&tx, member_id)?;
        if !current || b.pool_id != pool_id || b.member.runtime == runtime {
            return Ok(());
        }
        b.member.runtime = runtime.into();
        save_binding(&tx, &b, true)?;
        let (mut p, owner) = pool(&tx, pool_id)?;
        p.revision += 1;
        save_pool(&tx, &p)?;
        let ev = append_event(
            &tx,
            &p,
            "runtime_changed",
            Author::Service,
            format!("Member {member_id}: execution {runtime}."),
            Some(member_id.into()),
        )?;
        system_deliveries(&tx, &p, &ev, &bindings(&tx, pool_id)?, None)?;
        if matches!(runtime, "failed" | "lost") {
            let addr = owner_address(&tx, &owner)?;
            queue_delivery(
                &tx,
                pool_id,
                None,
                &addr,
                &format!("owner:{pool_id}"),
                notification(&p, &bindings(&tx, pool_id)?, &ev)?,
            )?;
        }
        tx.commit()?;
        Ok(())
    }
}
/// Applies a typed command inside the caller's single SQLite transaction.
fn execute(db: &Connection, actor: &Actor, command: &Command) -> Result<Reply, Fault> {
    if let Command::Create(c) = command {
        return create(db, actor, c, command);
    }
    if let Command::List(c) = command {
        return list(db, actor, c);
    }
    let pid = match command {
        Command::Get(g) => g.pool_id.as_str(),
        _ => command.change().ok_or(Fault::Invalid)?.pool_id.as_str(),
    };
    let (mut p, owner) = pool(db, pid)?;
    let mut roster = bindings(db, pid)?;
    let is_owner = owner == actor.key;
    let caller = roster
        .iter()
        .find(|b| {
            b.actor.as_deref() == Some(&actor.key)
                || (b.actor.is_none() && b.address.as_deref() == Some(&actor.address))
        })
        .cloned();
    if !is_owner && caller.is_none() {
        return Err(Fault::Forbidden);
    }
    if let Command::Get(g) = command {
        return view(db, p, roster, g, is_owner);
    }
    let c = command.change().ok_or(Fault::Invalid)?;
    authorize(command, is_owner, caller.as_ref())?;
    let replay_scope = if is_owner {
        format!("owner:{}:{pid}", actor.key)
    } else {
        format!(
            "member:{}",
            caller.as_ref().ok_or(Fault::Forbidden)?.member.member_id
        )
    };
    let digest = command.digest()?;
    if let Some(reply) = replay(db, &replay_scope, &c.request_key, &digest)? {
        return Ok(reply);
    }
    if p.closed {
        return Err(Fault::Closed);
    }
    if p.revision != c.expected_revision {
        return Err(Fault::Stale);
    }
    p.revision = p.revision.checked_add(1).ok_or(Fault::Internal)?;
    let author = if is_owner {
        Author::Leader
    } else {
        Author::Member(
            caller
                .as_ref()
                .ok_or(Fault::Forbidden)?
                .member
                .member_id
                .clone(),
        )
    };
    let mut created = None;
    let mut target = None;
    let mut direct_address = None;
    let mut direct_scope = None;
    let mut start_spec = None;
    let mut removed = None;
    let (kind, body, system) = match command {
        Command::Update(x) => {
            p.name = x.name.clone();
            p.purpose = x.purpose.clone();
            (
                "pool_updated",
                String::from("Pool name and purpose updated."),
                true,
            )
        }
        Command::Close(_) => {
            p.closed = true;
            stale(&mut p);
            for b in &roster {
                remove_binding(db, b, &p)?;
            }
            roster.clear();
            (
                "pool_closed",
                String::from("Pool closed; execution processes were not stopped."),
                true,
            )
        }
        Command::Add(x) => {
            if roster.len() >= MAX_MEMBERS {
                return Err(Fault::Conflict);
            }
            reserve(db, &x.address, None)?;
            let b = new_binding(&p, &x.name, &x.role, &x.task, Some(x.address.clone()));
            created = Some(b.member.member_id.clone());
            target = created.clone();
            save_binding(db, &b, true)?;
            roster.push(b);
            stale(&mut p);
            (
                "member_added",
                String::from("Member invited; awaiting verified onboarding acknowledgment."),
                true,
            )
        }
        Command::Start(x) => {
            if roster.len() >= MAX_MEMBERS {
                return Err(Fault::Conflict);
            }
            let b = new_binding(&p, &x.name, &x.role, &x.task, None);
            created = Some(b.member.member_id.clone());
            target = created.clone();
            save_binding(db, &b, true)?;
            roster.push(b);
            stale(&mut p);
            start_spec = Some(x.spec.clone());
            (
                "member_added",
                String::from(
                    "Agent start requested; member awaits native binding and verified join.",
                ),
                true,
            )
        }
        Command::MemberUpdate(x) => {
            let b = roster
                .iter_mut()
                .find(|b| b.member.member_id == x.member_id)
                .ok_or(Fault::Forbidden)?;
            b.member.name = x.name.clone();
            b.member.role = x.role.clone();
            b.member.task = x.task.clone();
            save_binding(db, b, true)?;
            target = Some(x.member_id.clone());
            stale(&mut p);
            (
                "assignment_changed",
                String::from("Member role, task or name updated."),
                true,
            )
        }
        Command::Remove(x) => {
            let i = roster
                .iter()
                .position(|b| b.member.member_id == x.member_id)
                .ok_or(Fault::Forbidden)?;
            let b = roster.remove(i);
            remove_binding(db, &b, &p)?;
            removed = Some(b);
            target = Some(x.member_id.clone());
            stale(&mut p);
            (
                "member_removed",
                String::from("Membership ended; execution process was not stopped."),
                true,
            )
        }
        Command::Join(_) => {
            if leader(db, actor)? {
                return Err(Fault::Forbidden);
            }
            let b = roster
                .iter_mut()
                .find(|b| {
                    b.member.member_id
                        == caller
                            .as_ref()
                            .map(|x| x.member.member_id.as_str())
                            .unwrap_or("")
                })
                .ok_or(Fault::Forbidden)?;
            if b.member.state != MemberState::Pending {
                return Err(Fault::Conflict);
            }
            let occupied: bool = db.query_row(
                "SELECT EXISTS(SELECT 1 FROM members WHERE current=1 AND actor=?1 AND id<>?2)",
                params![actor.key, b.member.member_id],
                |r| r.get(0),
            )?;
            if occupied {
                return Err(Fault::Conflict);
            }
            b.actor = Some(actor.key.clone());
            b.member.state = MemberState::Active;
            target = Some(b.member.member_id.clone());
            save_binding(db, b, true)?;
            stale(&mut p);
            (
                "member_joined",
                String::from("Member confirmed the current onboarding snapshot."),
                true,
            )
        }
        Command::Post(x) => ("message", x.body.clone(), false),
        Command::Send(x) => {
            let b = roster
                .iter()
                .find(|b| b.member.member_id == x.member_id)
                .ok_or(Fault::Forbidden)?;
            direct_address = Some(b.address.clone().unwrap_or_default());
            direct_scope = Some(scope(&b.member.member_id));
            target = Some(x.member_id.clone());
            ("direct_message", x.body.clone(), false)
        }
        Command::Notify(x) => {
            direct_address = Some(owner_address(db, &owner)?);
            direct_scope = Some(format!("owner:{pid}"));
            ("owner_message", x.body.clone(), false)
        }
        Command::Propose(x) => {
            if p.proposal
                .as_ref()
                .is_some_and(|x| x.state == ProposalState::Open)
            {
                return Err(Fault::Conflict);
            }
            let voters: Vec<_> = roster
                .iter()
                .filter(|b| b.member.state == MemberState::Active)
                .map(|b| b.member.member_id.clone())
                .collect();
            if voters.is_empty() {
                return Err(Fault::Conflict);
            }
            let frozen: Vec<_> = roster
                .iter()
                .filter(|b| b.member.state == MemberState::Active)
                .map(|b| (&b.member.member_id, &b.member.role, &b.member.task))
                .collect();
            let proposal_id = id();
            created = Some(proposal_id.clone());
            let proposal = Proposal {
                proposal_id,
                roster_key: format!("{:x}", Sha256::digest(encode(&frozen)?.as_bytes())),
                voters,
                result: x.result.clone(),
                criteria: x.criteria.clone(),
                state: ProposalState::Open,
                votes: BTreeMap::new(),
            };
            // Archive complete proposal content independently of the current bounded pool snapshot.
            p.proposal = Some(proposal);
            (
                "proposal_opened",
                format!("Result:\n{}\nCriteria:\n{}", x.result, x.criteria),
                true,
            )
        }
        Command::Vote(x) => {
            let member = &caller.as_ref().ok_or(Fault::Forbidden)?.member.member_id;
            let proposal = p.proposal.as_mut().ok_or(Fault::Stale)?;
            if proposal.state != ProposalState::Open
                || proposal.proposal_id != x.proposal_id
                || proposal.roster_key != x.roster_key
                || !proposal.voters.contains(member)
            {
                return Err(Fault::Stale);
            }
            proposal.votes.insert(
                member.clone(),
                Ballot {
                    choice: x.choice.clone(),
                    evidence: x.evidence.clone(),
                },
            );
            if proposal.voters.iter().all(|m| {
                proposal
                    .votes
                    .get(m)
                    .is_some_and(|b| b.choice == Choice::Ready)
            }) {
                proposal.state = ProposalState::Accepted;
            }
            (
                if proposal.state == ProposalState::Accepted {
                    "proposal_accepted"
                } else {
                    "vote_recorded"
                },
                format!(
                    "Proposal {}: {:?}.\n{}",
                    x.proposal_id, x.choice, x.evidence
                ),
                true,
            )
        }
        _ => return Err(Fault::Invalid),
    };
    save_pool(db, &p)?;
    let event = append_event(db, &p, kind, author, body, target.clone())?;
    if system {
        system_deliveries(
            db,
            &p,
            &event,
            &roster,
            caller.as_ref().map(|b| b.member.member_id.as_str()),
        )?;
    } else if matches!(command, Command::Send(_) | Command::Notify(_)) {
        let own_target = target.as_deref() == caller.as_ref().map(|b| b.member.member_id.as_str());
        if (!own_target || matches!(command, Command::Notify(_)))
            && let Some(address) = direct_address
        {
            queue_delivery(
                db,
                pid,
                target.as_deref(),
                &address,
                direct_scope.as_deref().ok_or(Fault::Internal)?,
                notification(&p, &roster, &event)?,
            )?;
        }
    } else {
        system_deliveries(
            db,
            &p,
            &event,
            &roster,
            caller.as_ref().map(|b| b.member.member_id.as_str()),
        )?;
    }
    if let Some(member_id) = created
        .as_deref()
        .filter(|_| matches!(command, Command::Add(_) | Command::Start(_)))
    {
        let b = roster
            .iter()
            .find(|b| b.member.member_id == member_id)
            .ok_or(Fault::Internal)?;
        let intro = onboarding(&p, &roster, &b.member)?;
        if let Some(address) = &b.address {
            queue_delivery(db, pid, Some(member_id), address, &scope(member_id), intro)?;
        } else if let Some(mut spec) = start_spec {
            let obj = spec.as_object_mut().ok_or(Fault::Invalid)?;
            let prompt = obj
                .get("task")
                .and_then(serde_json::Value::as_str)
                .ok_or(Fault::Invalid)?;
            obj.insert(
                "task".into(),
                serde_json::Value::String(format!("{prompt}\n\n{intro}")),
            );
            let required = obj
                .entry("required_mcp")
                .or_insert_with(|| serde_json::json!({}))
                .as_object_mut()
                .ok_or(Fault::Invalid)?;
            let tools = required
                .entry("agent-pool")
                .or_insert_with(|| serde_json::json!([]))
                .as_array_mut()
                .ok_or(Fault::Invalid)?;
            for name in [
                "pool_join",
                "pool_get",
                "pool_post",
                "pool_send_member",
                "pool_notify_owner",
                "pool_propose",
                "pool_vote",
                "pool_remove",
            ] {
                let v = serde_json::Value::String(name.into());
                if !tools.contains(&v) {
                    tools.push(v);
                }
            }
            queue(
                db,
                pid,
                Some(member_id),
                Work::Start {
                    spec,
                    request_key: format!("agent-pool.{pid}.{member_id}"),
                },
            )?;
        }
    }
    // A removed member receives only the independent final service notice, never the remaining roster.
    if let Some(b) = removed {
        final_notice(db, &p, &b)?;
    }
    let reply = Reply::Receipt(Receipt {
        pool_id: pid.into(),
        revision: p.revision,
        created_id: created,
        event,
        status: "committed; delivery pending".into(),
    });
    remember(db, &replay_scope, &c.request_key, &digest, &reply)?;
    Ok(reply)
}
/// Enforces tool-specific owner/member roles, including pending-member read/join restrictions.
fn authorize(command: &Command, owner: bool, caller: Option<&Binding>) -> Result<(), Fault> {
    let active = caller.is_some_and(|b| b.member.state == MemberState::Active);
    let allowed = match command {
        Command::Update(_)
        | Command::Close(_)
        | Command::Add(_)
        | Command::Start(_)
        | Command::MemberUpdate(_) => owner,
        Command::Join(_) => !owner && caller.is_some(),
        Command::Remove(x) => owner || caller.is_some_and(|b| b.member.member_id == x.member_id),
        Command::Vote(_) | Command::Notify(_) => !owner && active,
        Command::Post(_) | Command::Send(_) | Command::Propose(_) => owner || active,
        _ => false,
    };
    if allowed {
        Ok(())
    } else {
        Err(Fault::Forbidden)
    }
}
/// Creates a permanent global leader and pool atomically, preserving exact creation retries.
fn create(db: &Connection, actor: &Actor, c: &Create, command: &Command) -> Result<Reply, Fault> {
    let member: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM members WHERE current=1 AND (actor=?1 OR address=?2))",
        params![actor.key, actor.address],
        |r| r.get(0),
    )?;
    if member {
        return Err(Fault::Forbidden);
    }
    let scope = format!("create:{}", actor.key);
    let digest = command.digest()?;
    if let Some(reply) = replay(db, &scope, &c.request_key, &digest)? {
        return Ok(reply);
    }
    let address_owner: Option<String> = db
        .query_row(
            "SELECT actor FROM leaders WHERE address=?1",
            [&actor.address],
            |r| r.get(0),
        )
        .optional()?;
    if address_owner.as_ref().is_some_and(|x| x != &actor.key) {
        return Err(Fault::Conflict);
    }
    db.execute(
        "INSERT INTO leaders(actor,address) VALUES(?1,?2) ON CONFLICT(actor) DO NOTHING",
        params![actor.key, actor.address],
    )?;
    let p = Pool {
        pool_id: id(),
        name: c.name.clone(),
        purpose: c.purpose.clone(),
        revision: 1,
        closed: false,
        proposal: None,
    };
    db.execute(
        "INSERT INTO pools(id,owner,data) VALUES(?1,?2,?3)",
        params![p.pool_id, actor.key, encode(&p)?],
    )?;
    let event = append_event(
        db,
        &p,
        "pool_created",
        Author::Leader,
        "Persistent pool created; leader is outside its membership.".into(),
        None,
    )?;
    let reply = Reply::Receipt(Receipt {
        pool_id: p.pool_id,
        revision: 1,
        created_id: None,
        event,
        status: "committed".into(),
    });
    remember(db, &scope, &c.request_key, &digest, &reply)?;
    Ok(reply)
}
/// Returns ten accessible pools with an exclusive ID cursor, omitting potentially large proposal data.
fn list(db: &Connection, actor: &Actor, c: &List) -> Result<Reply, Fault> {
    let mut stmt=db.prepare("SELECT p.data FROM pools p WHERE p.id>?3 AND (p.owner=?1 OR EXISTS(SELECT 1 FROM members m WHERE m.pool=p.id AND m.current=1 AND (m.actor=?1 OR (m.actor IS NULL AND m.address=?2)))) ORDER BY p.id LIMIT 11")?;
    let mut pools: Vec<Pool> = stmt
        .query_map(
            params![actor.key, actor.address, c.after.as_deref().unwrap_or("")],
            |r| r.get::<_, String>(0),
        )?
        .map(|r| {
            let mut p: Pool = decode(&r?)?;
            p.proposal = None;
            Ok(p)
        })
        .collect::<Result<_, Fault>>()?;
    let more = pools.len() > 10;
    pools.truncate(10);
    let next = pools.last().map(|p| p.pool_id.clone());
    Ok(Reply::List {
        pools,
        next_after: next,
        has_more: more,
    })
}
/// Projects exactly one bounded section; cursors advance only across returned rows.
fn view(
    db: &Connection,
    mut p: Pool,
    roster: Vec<Binding>,
    g: &Get,
    owner: bool,
) -> Result<Reply, Fault> {
    let sql_after = i64::try_from(g.after).map_err(|_| Fault::Invalid)?;
    if let Some(pid) = &g.proposal_id {
        let raw: Option<String> = db
            .query_row(
                "SELECT data FROM proposals WHERE id=?1 AND pool=?2",
                params![pid, p.pool_id],
                |r| r.get(0),
            )
            .optional()?;
        p.proposal = Some(decode(&raw.ok_or(Fault::Forbidden)?)?);
    }
    let active = roster
        .iter()
        .filter(|b| b.member.state == MemberState::Active)
        .count();
    let pending = roster.len() - active;
    let mut members = Vec::new();
    let mut events = Vec::new();
    let mut deliveries = Vec::new();
    let mut next = g.after;
    let mut more = false;
    let mut private = Vec::new();
    match g.section {
        Section::Overview | Section::Members => {
            p.proposal = None;
            let offset = usize::try_from(g.after).map_err(|_| Fault::Invalid)?;
            private = roster
                .iter()
                .skip(offset)
                .take(if owner { 2 } else { 5 })
                .cloned()
                .collect();
            members = private.iter().map(|b| b.member.clone()).collect();
            next = g.after + members.len() as u64;
            more = next < (roster.len() as u64);
        }
        Section::History => {
            p.proposal = None;
            let mut budget = 0;
            let mut stmt = db.prepare(
                "SELECT id,data FROM events WHERE pool=?1 AND id>?2 ORDER BY id LIMIT 4",
            )?;
            let rows = stmt.query_map(params![p.pool_id, sql_after], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
            })?;
            for row in rows {
                let (n, s) = row?;
                let n = u64::try_from(n).map_err(|_| Fault::Internal)?;
                if events.len() == 3 || budget + s.len() > 10000 {
                    more = true;
                    break;
                }
                let mut e: Event = decode(&s)?;
                e.event_id = n;
                budget += s.len();
                next = n;
                events.push(e);
            }
        }
        Section::Proposal => {
            if let Some(proposal) = p.proposal.as_mut() {
                proposal.votes.clear();
            }
        }
        Section::Votes => {
            if let Some(proposal) = p.proposal.as_mut() {
                let offset = usize::try_from(g.after).map_err(|_| Fault::Invalid)?;
                let len = proposal.votes.len();
                proposal.votes = proposal
                    .votes
                    .iter()
                    .skip(offset)
                    .take(3)
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                next = g.after + proposal.votes.len() as u64;
                more = next < len as u64;
                proposal.result.clear();
                proposal.criteria.clear();
                proposal.voters.clear();
            }
        }
        Section::Deliveries => {
            p.proposal = None;
            let mut stmt=db.prepare("SELECT sequence,id,member,state,data FROM effects WHERE pool=?1 AND sequence>?2 ORDER BY sequence LIMIT 21")?;
            let rows = stmt.query_map(params![p.pool_id, sql_after], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                ))
            })?;
            for row in rows {
                let (sequence, id, member_id, state, data) = row?;
                let sequence = u64::try_from(sequence).map_err(|_| Fault::Internal)?;
                if deliveries.len() == 20 {
                    more = true;
                    break;
                }
                let e: Effect = decode(&data)?;
                let operation = match e.work {
                    Work::Deliver { .. } => "deliver",
                    Work::Retire { .. } => "retire",
                    Work::Start { .. } => "start",
                };
                deliveries.push(Delivery {
                    operation_id: id,
                    member_id,
                    operation: operation.into(),
                    state,
                });
                next = sequence;
            }
        }
    }
    let view = Box::new(View {
        section: g.section.clone(),
        pool: p,
        members,
        active,
        pending,
        events,
        deliveries,
        next_after: next,
        has_more: more,
    });
    if owner {
        Ok(Reply::OwnerView {
            view,
            bindings: private,
        })
    } else {
        Ok(Reply::View(view))
    }
}
/// Loads a pool and owner without exposing whether an inaccessible identifier exists.
fn pool(db: &Connection, id: &str) -> Result<(Pool, String), Fault> {
    let row: Option<(String, String)> = db
        .query_row("SELECT data,owner FROM pools WHERE id=?1", [id], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .optional()?;
    let (data, owner) = row.ok_or(Fault::Forbidden)?;
    Ok((decode(&data)?, owner))
}
/// Replaces only the bounded current pool snapshot.
fn save_pool(db: &Connection, p: &Pool) -> Result<(), Fault> {
    db.execute(
        "UPDATE pools SET data=?2 WHERE id=?1",
        params![p.pool_id, encode(p)?],
    )?;
    if let Some(proposal) = &p.proposal {
        let state = match proposal.state {
            ProposalState::Open => "open",
            ProposalState::Accepted => "accepted",
            ProposalState::Stale => "stale",
        };
        db.execute("INSERT INTO proposals(id,pool,state,data) VALUES(?1,?2,?3,?4) ON CONFLICT(id) DO UPDATE SET state=excluded.state,data=excluded.data WHERE proposals.state='open'",params![proposal.proposal_id,p.pool_id,state,encode(proposal)?])?;
    }
    Ok(())
}
/// Loads current members in stable membership-ID order.
fn bindings(db: &Connection, pool: &str) -> Result<Vec<Binding>, Fault> {
    let mut stmt =
        db.prepare("SELECT data FROM members WHERE pool=?1 AND current=1 ORDER BY id")?;
    stmt.query_map([pool], |r| r.get::<_, String>(0))?
        .map(|r| decode(&r?))
        .collect()
}
/// Loads an exact retained incarnation and whether it still has access.
fn binding_any(db: &Connection, id: &str) -> Result<(Binding, bool), Fault> {
    let (s, current): (String, bool) =
        db.query_row("SELECT data,current FROM members WHERE id=?1", [id], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?;
    Ok((decode(&s)?, current))
}
/// Writes private binding and indexed uniqueness columns together.
fn save_binding(db: &Connection, b: &Binding, current: bool) -> Result<(), Fault> {
    db.execute("INSERT INTO members(id,pool,actor,address,current,data) VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(id) DO UPDATE SET actor=excluded.actor,address=excluded.address,current=excluded.current,data=excluded.data",params![b.member.member_id,b.pool_id,b.actor,b.address,current,encode(b)?])?;
    Ok(())
}
/// Builds a fresh pending incarnation without claiming the target's actor identity.
fn new_binding(p: &Pool, name: &str, role: &str, task: &str, address: Option<String>) -> Binding {
    Binding {
        member: Member {
            member_id: id(),
            name: name.into(),
            role: role.into(),
            task: task.into(),
            state: MemberState::Pending,
            runtime: "unknown".into(),
        },
        pool_id: p.pool_id.clone(),
        actor: None,
        address,
        run_id: None,
        run_sequence: None,
    }
}
/// Detects permanent leader status by verified actor or canonical address.
fn leader(db: &Connection, a: &Actor) -> Result<bool, Fault> {
    Ok(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM leaders WHERE actor=?1 OR address=?2)",
        params![a.key, a.address],
        |r| r.get(0),
    )?)
}
/// Rejects any leader address or current reservation, except the same binding being finalized.
fn reserve(db: &Connection, address: &str, except: Option<&str>) -> Result<(), Fault> {
    let busy:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM leaders WHERE address=?1) OR EXISTS(SELECT 1 FROM members WHERE current=1 AND address=?1 AND id<>?2)",params![address,except.unwrap_or("")],|r|r.get(0))?;
    if busy { Err(Fault::Conflict) } else { Ok(()) }
}
/// Resolves an owner privately for the explicit notification and failure-only paths.
fn owner_address(db: &Connection, owner: &str) -> Result<String, Fault> {
    Ok(
        db.query_row("SELECT address FROM leaders WHERE actor=?1", [owner], |r| {
            r.get(0)
        })?,
    )
}
/// Makes only an unfinished proposal stale; accepted results remain immutable.
fn stale(p: &mut Pool) {
    if let Some(x) = p.proposal.as_mut()
        && x.state == ProposalState::Open
    {
        x.state = ProposalState::Stale;
    }
}
/// Retires access and locally queued work without claiming recall of inflight provider effects.
fn remove_binding(db: &Connection, b: &Binding, p: &Pool) -> Result<(), Fault> {
    save_binding(db, b, false)?;
    db.execute(
        "UPDATE effects SET state='cancelled' WHERE member=?1 AND state IN ('queued','awaiting_binding')",
        [&b.member.member_id],
    )?;
    queue(
        db,
        &p.pool_id,
        Some(&b.member.member_id),
        Work::Retire {
            scope: scope(&b.member.member_id),
        },
    )?;
    if p.closed {
        final_notice(db, p, b)?;
    }
    Ok(())
}
/// Sends exactly one independent membership-ending notice, with no remaining roster or private data.
fn final_notice(db: &Connection, p: &Pool, b: &Binding) -> Result<(), Fault> {
    let possible_start:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM effects WHERE member=?1 AND state IN ('inflight','unknown','custody'))",[&b.member.member_id],|r|r.get(0))?;
    if b.address.is_some() || b.run_id.is_some() || possible_start {
        let address = b.address.as_deref().unwrap_or("");
        queue_delivery(
            db,
            &p.pool_id,
            Some(&b.member.member_id),
            address,
            &format!("final:{}", b.member.member_id),
            format!(
                "Membership ended. Pool {}. Member {}. Access revoked; process not stopped.",
                p.pool_id, b.member.member_id
            ),
        )?;
    }
    Ok(())
}
/// Stable producer-private Bridge scope for one never-reused membership incarnation.
fn scope(member: &str) -> String {
    format!("agent-pool:member:{member}")
}
/// Appends safe event data and returns its actual monotonic SQLite cursor.
fn append_event(
    db: &Connection,
    p: &Pool,
    kind: &str,
    author: Author,
    body: String,
    recipient: Option<String>,
) -> Result<Event, Fault> {
    let mut e = Event {
        event_id: 0,
        revision: p.revision,
        kind: kind.into(),
        author,
        body,
        recipient,
    };
    db.execute(
        "INSERT INTO events(pool,data) VALUES(?1,?2)",
        params![p.pool_id, encode(&e)?],
    )?;
    e.event_id = db.last_insert_rowid() as u64;
    Ok(e)
}
/// Enqueues one immutable provider intent within the surrounding business transaction.
fn queue(db: &Connection, pool: &str, member: Option<&str>, work: Work) -> Result<(), Fault> {
    let state = if matches!(&work,Work::Deliver{address,..}if address.is_empty()) {
        "awaiting_binding"
    } else {
        "queued"
    };
    let e = Effect {
        effect_id: id(),
        pool_id: pool.into(),
        member_id: member.map(str::to_owned),
        work,
        state: state.into(),
    };
    db.execute(
        "INSERT INTO effects(id,pool,member,state,data) VALUES(?1,?2,?3,?4,?5)",
        params![e.effect_id, pool, member, state, encode(&e)?],
    )?;
    Ok(())
}
/// Enqueues a bounded exact payload; over-budget output aborts the entire originating transaction.
fn queue_delivery(
    db: &Connection,
    pool: &str,
    member: Option<&str>,
    address: &str,
    scope: &str,
    text: String,
) -> Result<(), Fault> {
    if text.len() > 16384 {
        return Err(Fault::Invalid);
    }
    queue(
        db,
        pool,
        member,
        Work::Deliver {
            address: address.into(),
            scope: scope.into(),
            text,
        },
    )
}
/// Sends safe system/message events to current members, excluding the caller's redundant wakeup.
fn system_deliveries(
    db: &Connection,
    p: &Pool,
    e: &Event,
    roster: &[Binding],
    skip: Option<&str>,
) -> Result<(), Fault> {
    let text = notification(p, roster, e)?;
    for b in roster {
        if skip == Some(b.member.member_id.as_str()) {
            continue;
        }
        {
            let address = b.address.as_deref().unwrap_or("");
            queue_delivery(
                db,
                &p.pool_id,
                Some(&b.member.member_id),
                address,
                &scope(&b.member.member_id),
                text.clone(),
            )?;
        }
    }
    Ok(())
}
/// Builds a bounded safe roster summary; complete tasks are available through paged pool_get.
fn roster_text(roster: &[Binding]) -> String {
    let mut out = String::from(
        "Brief roster; abbreviated labels/tasks have …; full assignments: pool_get section=members.\n",
    );
    for b in roster {
        out.push_str(&format!(
            "{} | {} | role={} | task={} | {:?}\n",
            b.member.member_id,
            brief(&b.member.name, 24),
            brief(&b.member.role, 40),
            brief(&b.member.task, 48),
            b.member.state
        ));
    }
    out
}
/// Quotes a descriptive notification preview on a UTF-8 boundary; exact content stays retrievable.
fn brief(s: &str, limit: usize) -> String {
    let mut end = s.len().min(limit);
    while !s.is_char_boundary(end) {
        end -= 1
    }
    let value = if end < s.len() {
        format!("{}…", &s[..end])
    } else {
        s.into()
    };
    serde_json::to_string(&value).unwrap_or_else(|_| String::from("\"unavailable\""))
}
/// Produces a safe notification with the current roster and version; never includes private bindings.
fn notification(p: &Pool, roster: &[Binding], e: &Event) -> Result<String, Fault> {
    let active = roster
        .iter()
        .filter(|b| b.member.state == MemberState::Active)
        .count();
    let body = encode(&e.body)?;
    let text = format!(
        "Pool {} revision {}. Event {}: {}\nBody: {}\nConfirmed {}; pending {}.\n{}Use pool_get for current details; older events never replace newer state.",
        p.pool_id,
        p.revision,
        e.event_id,
        e.kind,
        body,
        active,
        roster.len() - active,
        roster_text(roster)
    );
    if text.len() > 16384 {
        Err(Fault::Invalid)
    } else {
        Ok(text)
    }
}
/// Creates mandatory onboarding with communication rules and a version-specific join instruction.
fn onboarding(p: &Pool, roster: &[Binding], member: &Member) -> Result<String, Fault> {
    let text = format!(
        "Agent Pool onboarding\nPool {}: {}\nPurpose: {}\nYour member_id: {}\nRole: {}\nTask: {}\nCurrent revision: {}\n{}\nLeader is external and is not a member or voter. pool_post reaches members only; pool_send_member reaches one current peer; pool_notify_owner reaches the hidden owner. All messages share history. Use local member IDs only. Read pool_get then confirm the current revision with pool_join. Pending members cannot vote. Removed membership loses access. Completion or consensus does not close the pool. Separate Bridge remains independent.\n",
        p.pool_id,
        p.name,
        p.purpose,
        member.member_id,
        member.role,
        member.task,
        p.revision,
        roster_text(roster)
    );
    if text.len() > 16384 {
        Err(Fault::Invalid)
    } else {
        Ok(text)
    }
}
/// Records a delivery failure and separately wakes the external owner with a safe intervention request.
fn failure_event(
    db: &Connection,
    pool_id: &str,
    member: Option<&str>,
    body: &str,
) -> Result<(), Fault> {
    let before: i64 = db.query_row("SELECT COALESCE(MAX(sequence),0) FROM effects", [], |r| {
        r.get(0)
    })?;
    let (mut p, owner) = pool(db, pool_id)?;
    p.revision += 1;
    save_pool(db, &p)?;
    let e = append_event(
        db,
        &p,
        "delivery_failed",
        Author::Service,
        body.into(),
        member.map(str::to_owned),
    )?;
    let roster = bindings(db, pool_id)?;
    system_deliveries(db, &p, &e, &roster, None)?;
    if member.is_some() {
        let address = owner_address(db, &owner)?;
        queue_delivery(
            db,
            pool_id,
            None,
            &address,
            &format!("owner:{pool_id}"),
            notification(&p, &roster, &e)?,
        )?;
    }
    db.execute(
        "UPDATE effects SET failure_notice=1 WHERE sequence>?1",
        [before],
    )?;
    Ok(())
}
/// Loads private effect data with authoritative SQL state, including after crash recovery.
fn effect(db: &Connection, id: &str) -> Result<Effect, Fault> {
    let (data, state): (String, String) =
        db.query_row("SELECT data,state FROM effects WHERE id=?1", [id], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?;
    let mut e: Effect = decode(&data)?;
    e.state = state;
    Ok(e)
}
/// Returns an exact retained receipt or rejects idempotency-key reuse with different intent.
fn replay(db: &Connection, scope: &str, key: &str, digest: &str) -> Result<Option<Reply>, Fault> {
    let row: Option<(String, String)> = db
        .query_row(
            "SELECT digest,receipt FROM requests WHERE scope=?1 AND key=?2",
            params![scope, key],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    match row {
        None => Ok(None),
        Some((d, r)) if d == digest => Ok(Some(decode(&r)?)),
        Some(_) => Err(Fault::Conflict),
    }
}
/// Saves one complete safe receipt in the same transaction as its effect intents.
fn remember(
    db: &Connection,
    scope: &str,
    key: &str,
    digest: &str,
    reply: &Reply,
) -> Result<(), Fault> {
    db.execute(
        "INSERT INTO requests(scope,key,digest,receipt) VALUES(?1,?2,?3,?4)",
        params![scope, key, digest, encode(reply)?],
    )?;
    Ok(())
}
/// Encodes trusted typed durable state; serialization errors never expose source data.
fn encode<T: Serialize>(value: &T) -> Result<String, Fault> {
    serde_json::to_string(value).map_err(|_| Fault::Internal)
}
/// Decodes trusted database state; corruption is an internal error rather than an empty result.
fn decode<T: DeserializeOwned>(value: &str) -> Result<T, Fault> {
    serde_json::from_str(value).map_err(|_| Fault::Internal)
}

/// Isolated state-machine regressions; authenticated actors here are synthetic fixtures only.
#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "Assertions in isolated temporary SQLite fixtures"
)]
mod tests {
    use super::*;
    /// Isolated store fixture rooted exclusively in the task's approved TMPDIR.
    fn fixture() -> (tempfile::TempDir, Store) {
        let root = std::env::var_os("TMPDIR").expect("task TMPDIR required");
        let d = tempfile::tempdir_in(root).unwrap();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let s = Store::open(&d.path().join("pool.sqlite")).unwrap();
        (d, s)
    }
    /// Authenticated synthetic actor used only at the domain test boundary, never a production bypass.
    fn actor(label: &str) -> Actor {
        Actor::verified(format!("codex:test:store:{label}"), label, "root").unwrap()
    }
    /// Creates a pool and returns its opaque ID.
    fn make(s: &mut Store, a: &Actor, key: &str) -> String {
        match s
            .execute(
                a,
                &Command::Create(Create {
                    request_key: key.into(),
                    name: "Pool".into(),
                    purpose: "Joint work".into(),
                }),
            )
            .unwrap()
        {
            Reply::Receipt(r) => r.pool_id,
            _ => panic!("receipt"),
        }
    }
    /// Builds current-version mutation preconditions with a fresh idempotency key.
    fn change(s: &Store, pid: &str) -> Change {
        Change {
            pool_id: pid.into(),
            expected_revision: pool(&s.db, pid).unwrap().0.revision,
            request_key: id(),
        }
    }
    /// Invites an actor and returns its unique pending incarnation.
    fn add(s: &mut Store, owner: &Actor, pid: &str, a: &Actor) -> String {
        let c = change(s, pid);
        match s
            .execute(
                owner,
                &Command::Add(Add {
                    change: c,
                    address: a.address.clone(),
                    name: "Member".into(),
                    role: "Implement".into(),
                    task: "Check the result".into(),
                }),
            )
            .unwrap()
        {
            Reply::Receipt(r) => r.created_id.unwrap(),
            _ => panic!("receipt"),
        }
    }
    /// Confirms an invitation using the latest snapshot revision.
    fn join(s: &mut Store, a: &Actor, pid: &str) {
        let c = change(s, pid);
        let checked = s.join_binding(a, pid).unwrap();
        s.execute_join(a, &Command::Join(c), &checked).unwrap();
    }
    /// Reads a member-safe snapshot without asserting owner-only shape.
    fn get(s: &mut Store, a: &Actor, pid: &str) -> Result<Reply, Fault> {
        s.execute(
            a,
            &Command::Get(Get {
                pool_id: pid.into(),
                after: 0,
                section: Section::Overview,
                proposal_id: None,
            }),
        )
    }
    /// Counts durable rows in a test-selected closed table name.
    fn count(s: &Store, table: &str) -> i64 {
        s.db.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    }
    /// One global leader owns multiple pools and can never join any, including another owner's pool.
    #[test]
    fn global_leader_survives_three_pools_and_close() {
        let (_d, mut s) = fixture();
        let lead = actor("lead");
        let other = actor("other");
        let pools: Vec<_> = (0..3)
            .map(|i| make(&mut s, &lead, &format!("create{i}")))
            .collect();
        let foreign = make(&mut s, &other, "foreign");
        for p in pools.iter().chain([&foreign]) {
            let own = if p == &foreign { &other } else { &lead };
            let c = change(&s, p);
            assert!(matches!(
                s.execute(
                    own,
                    &Command::Add(Add {
                        change: c,
                        address: lead.address.clone(),
                        name: "Alias".into(),
                        role: "Role".into(),
                        task: "Task".into()
                    })
                ),
                Err(Fault::Conflict)
            ));
        }
        let c = change(&s, &pools[0]);
        s.execute(&lead, &Command::Close(c)).unwrap();
        assert!(leader(&s.db, &lead).unwrap());
        assert_eq!(count(&s, "leaders"), 2);
    }
    /// Pending reservation and confirmed membership both exclude concurrent membership and leadership.
    #[test]
    fn member_reservations_are_global() {
        let (_d, mut s) = fixture();
        let lead = actor("lead");
        let a = actor("a");
        let p = make(&mut s, &lead, "one");
        let p2 = make(&mut s, &lead, "two");
        add(&mut s, &lead, &p, &a);
        let c = change(&s, &p2);
        assert!(matches!(
            s.execute(
                &lead,
                &Command::Add(Add {
                    change: c,
                    address: a.address.clone(),
                    name: "Alias".into(),
                    role: "Role".into(),
                    task: "Task".into()
                })
            ),
            Err(Fault::Conflict)
        ));
        let create = Command::Create(Create {
            request_key: "own".into(),
            name: "Own".into(),
            purpose: "Own".into(),
        });
        assert!(matches!(s.execute(&a, &create), Err(Fault::Forbidden)));
        join(&mut s, &a, &p);
        assert!(matches!(s.execute(&a, &create), Err(Fault::Forbidden)));
    }
    /// Post wakes peers only; explicit owner notification uses the hidden owner binding.
    #[test]
    fn audiences_and_public_views_exclude_native_addresses() {
        let (_d, mut s) = fixture();
        let lead = actor("SECRET_OWNER");
        let a = actor("SECRET_A");
        let b = actor("SECRET_B");
        let p = make(&mut s, &lead, "one");
        let amid = add(&mut s, &lead, &p, &a);
        join(&mut s, &a, &p);
        add(&mut s, &lead, &p, &b);
        join(&mut s, &b, &p);
        s.db.execute("UPDATE effects SET state='accepted'", [])
            .unwrap();
        let c = change(&s, &p);
        let reply = s
            .execute(
                &a,
                &Command::Post(Message {
                    change: c,
                    body: "hello".into(),
                }),
            )
            .unwrap();
        let e = s.next_effect().unwrap().unwrap();
        assert!(matches!(e.work,Work::Deliver{ref address,..}if address==&b.address));
        assert!(s.next_effect().unwrap().is_none());
        for reply in [reply, get(&mut s, &a, &p).unwrap()] {
            let text = encode(&reply).unwrap();
            assert!(!text.contains("SECRET_"));
            assert!(text.contains(&p));
        }
        let c = change(&s, &p);
        s.execute(
            &a,
            &Command::Notify(Message {
                change: c,
                body: "Need owner".into(),
            }),
        )
        .unwrap();
        let e = s.next_effect().unwrap().unwrap();
        assert!(matches!(e.work,Work::Deliver{ref address,..}if address==&lead.address));
        assert_ne!(amid, lead.key);
    }
    /// Removal revokes reads/actions before replay and readmission never reuses membership IDs.
    #[test]
    fn removal_cancels_queued_but_preserves_unknown_and_retires_scope() {
        let (_d, mut s) = fixture();
        let lead = actor("lead");
        let a = actor("a");
        let p = make(&mut s, &lead, "one");
        let m = add(&mut s, &lead, &p, &a);
        join(&mut s, &a, &p);
        let held = s.next_effect().unwrap().unwrap();
        let c = change(&s, &p);
        let post = Command::Post(Message {
            change: c,
            body: "saved".into(),
        });
        s.execute(&a, &post).unwrap();
        let c = change(&s, &p);
        s.execute(
            &lead,
            &Command::Remove(Remove {
                change: c,
                member_id: m.clone(),
            }),
        )
        .unwrap();
        assert!(matches!(get(&mut s, &a, &p), Err(Fault::Forbidden)));
        assert!(matches!(s.execute(&a, &post), Err(Fault::Forbidden)));
        assert_eq!(effect(&s.db, &held.effect_id).unwrap().state, "inflight");
        let queued: Vec<_> = {
            let mut v = Vec::new();
            while let Some(e) = s.next_effect().unwrap() {
                v.push(e)
            }
            v
        };
        assert_eq!(
            queued
                .iter()
                .filter(|e| matches!(e.work, Work::Retire { .. }))
                .count(),
            1
        );
        assert_eq!(
            queued
                .iter()
                .filter(
                    |e| matches!(e.work,Work::Deliver{ref scope,..}if scope.starts_with("final:"))
                )
                .count(),
            1
        );
        let next = add(&mut s, &lead, &p, &a);
        assert_ne!(m, next);
    }
    /// Exact mutation replay returns the original receipt; changed intent cannot reuse its key.
    #[test]
    fn idempotency_and_join_replay_precede_revision_fence() {
        let (_d, mut s) = fixture();
        let lead = actor("lead");
        let a = actor("a");
        let p = make(&mut s, &lead, "one");
        add(&mut s, &lead, &p, &a);
        let join = Command::Join(change(&s, &p));
        let checked = s.join_binding(&a, &p).unwrap();
        let first = s.execute_join(&a, &join, &checked).unwrap();
        let before = count(&s, "events");
        let checked = s.join_binding(&a, &p).unwrap();
        assert_eq!(
            encode(&first).unwrap(),
            encode(&s.execute_join(&a, &join, &checked).unwrap()).unwrap()
        );
        assert_eq!(count(&s, "events"), before);
        let c = change(&s, &p);
        let mut msg = Message {
            change: c,
            body: "first".into(),
        };
        let cmd = Command::Post(msg.clone());
        let first = s.execute(&a, &cmd).unwrap();
        assert_eq!(
            encode(&first).unwrap(),
            encode(&s.execute(&a, &cmd).unwrap()).unwrap()
        );
        msg.body = "different".into();
        assert!(matches!(
            s.execute(&a, &Command::Post(msg)),
            Err(Fault::Conflict)
        ));
    }
    /// Consensus requires every frozen confirmed member, excludes leader, and leaves accepted data immutable.
    #[test]
    fn consensus_blocks_revokes_and_survives_assignment_change() {
        let (_d, mut s) = fixture();
        let lead = actor("lead");
        let a = actor("a");
        let b = actor("b");
        let p = make(&mut s, &lead, "one");
        let aid = add(&mut s, &lead, &p, &a);
        join(&mut s, &a, &p);
        add(&mut s, &lead, &p, &b);
        join(&mut s, &b, &p);
        let c = change(&s, &p);
        s.execute(
            &lead,
            &Command::Propose(Propose {
                change: c,
                result: "Result".into(),
                criteria: "Evidence".into(),
            }),
        )
        .unwrap();
        let pr = pool(&s.db, &p).unwrap().0.proposal.unwrap();
        for (who, choice) in [
            (&lead, Choice::Ready),
            (&a, Choice::Ready),
            (&b, Choice::Block),
            (&a, Choice::Revoke),
            (&b, Choice::Ready),
            (&a, Choice::Ready),
        ] {
            let c = change(&s, &p);
            let cmd = Command::Vote(Vote {
                change: c,
                proposal_id: pr.proposal_id.clone(),
                roster_key: pr.roster_key.clone(),
                choice,
                evidence: "checked".into(),
            });
            if who.key == lead.key {
                assert!(matches!(s.execute(who, &cmd), Err(Fault::Forbidden)));
            } else {
                s.execute(who, &cmd).unwrap();
            }
        }
        let accepted = pool(&s.db, &p).unwrap().0.proposal.unwrap();
        assert_eq!(accepted.state, ProposalState::Accepted);
        let c = change(&s, &p);
        s.execute(
            &lead,
            &Command::MemberUpdate(MemberUpdate {
                change: c,
                member_id: aid,
                name: "A".into(),
                role: "New role".into(),
                task: "New task".into(),
            }),
        )
        .unwrap();
        let current = pool(&s.db, &p).unwrap().0;
        assert!(!current.closed);
        assert_eq!(
            encode(&accepted).unwrap(),
            encode(&current.proposal.unwrap()).unwrap()
        );
    }
    /// Pending members cannot vote; membership changes stale unfinished proposals.
    #[test]
    fn pending_member_and_stale_roster_cannot_vote() {
        let (_d, mut s) = fixture();
        let lead = actor("lead");
        let a = actor("a");
        let b = actor("b");
        let p = make(&mut s, &lead, "one");
        add(&mut s, &lead, &p, &a);
        join(&mut s, &a, &p);
        let c = change(&s, &p);
        s.execute(
            &a,
            &Command::Propose(Propose {
                change: c,
                result: "R".into(),
                criteria: "C".into(),
            }),
        )
        .unwrap();
        let pr = pool(&s.db, &p).unwrap().0.proposal.unwrap();
        add(&mut s, &lead, &p, &b);
        assert_eq!(
            pool(&s.db, &p).unwrap().0.proposal.unwrap().state,
            ProposalState::Stale
        );
        let c = change(&s, &p);
        let vote = Command::Vote(Vote {
            change: c,
            proposal_id: pr.proposal_id,
            roster_key: pr.roster_key,
            choice: Choice::Ready,
            evidence: "checked".into(),
        });
        assert!(matches!(s.execute(&b, &vote), Err(Fault::Forbidden)));
        assert!(matches!(s.execute(&a, &vote), Err(Fault::Stale)));
    }
    /// Crash recovery preserves uncertain effects and a second resident cannot take the writer lease.
    #[test]
    fn crash_recovery_and_frozen_publication_are_fail_closed() {
        let (d, mut s) = fixture();
        assert!(matches!(
            Store::open(&d.path().join("pool.sqlite")),
            Err(Fault::Conflict)
        ));
        let lead = actor("lead");
        let a = actor("a");
        let p = make(&mut s, &lead, "one");
        add(&mut s, &lead, &p, &a);
        let e = s.next_effect().unwrap().unwrap();
        let original =
            serde_json::json!({"destination":a.address,"event_id":e.effect_id,"payload":"frozen"});
        s.freeze_publication(&e.effect_id, "pool", &original)
            .unwrap();
        assert!(matches!(
            s.freeze_publication(&e.effect_id, "other", &original),
            Err(Fault::Conflict)
        ));
        drop(s);
        let mut s = Store::open(&d.path().join("pool.sqlite")).unwrap();
        let unknown = s.pending_unknown().unwrap();
        assert!(unknown.iter().any(|x| x.effect_id == e.effect_id));
        assert_eq!(
            s.freeze_publication(&e.effect_id, "pool", &original)
                .unwrap()
                .1,
            original
        );
    }
    /// Run intent keeps the original enriched specification and immediate admission across removal.
    #[test]
    fn run_admission_is_durable_before_native_binding() {
        let (_d, mut s) = fixture();
        let lead = actor("lead");
        let p = make(&mut s, &lead, "one");
        let c = change(&s, &p);
        let reply=s.execute(&lead,&Command::Start(Start{change:c,name:"Run member".into(),role:"Tester".into(),task:"Verify".into(),spec:serde_json::json!({"task":"Original","workdir":"/known","provider":"codex"})})).unwrap();
        let mid = match reply {
            Reply::Receipt(r) => r.created_id.unwrap(),
            _ => panic!("receipt"),
        };
        let effect = s.next_effect().unwrap().unwrap();
        let Work::Start {
            ref spec,
            ref request_key,
        } = effect.work
        else {
            panic!("start")
        };
        assert!(request_key.starts_with("agent-pool."));
        assert!(spec["task"].as_str().unwrap().starts_with("Original"));
        assert!(spec["task"].as_str().unwrap().contains("pool_join"));
        assert!(
            spec["required_mcp"]["agent-pool"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("pool_join"))
        );
        s.record_run_admission(&effect.effect_id, "ag-real", 1)
            .unwrap();
        assert_eq!(
            binding_any(&s.db, &mid).unwrap().0.run_id.as_deref(),
            Some("ag-real")
        );
        let c = change(&s, &p);
        s.execute(
            &lead,
            &Command::Remove(Remove {
                change: c,
                member_id: mid.clone(),
            }),
        )
        .unwrap();
        s.bind_run(&effect.effect_id, "codex:test:store:new")
            .unwrap();
        assert!(!binding_any(&s.db, &mid).unwrap().1);
        assert!(s.observation_targets().unwrap().is_empty());
        let mut final_count = 0;
        while let Some(e) = s.next_effect().unwrap() {
            if let Work::Deliver { scope, text, .. } = e.work {
                assert!(scope.starts_with("final:"));
                assert!(text.contains("Access revoked"));
                final_count += 1;
            }
        }
        assert_eq!(final_count, 1);
        s.bind_run(&effect.effect_id, "codex:test:store:new")
            .unwrap();
        assert!(s.next_effect().unwrap().is_none());
    }
    /// Pending Run recipients keep messages until their exact private binding becomes available.
    #[test]
    fn pending_messages_wait_for_binding_and_never_change_payload() {
        let (_d, mut s) = fixture();
        let lead = actor("lead");
        let p = make(&mut s, &lead, "one");
        let c = change(&s, &p);
        let reply=s.execute(&lead,&Command::Start(Start{change:c,name:"Run".into(),role:"Test".into(),task:"Verify".into(),spec:serde_json::json!({"task":"Original","provider":"codex","model":"test","profile":"implement","workdir":"/known"})})).unwrap();
        let mid = match reply {
            Reply::Receipt(r) => r.created_id.unwrap(),
            _ => panic!("receipt"),
        };
        let start = s.next_effect().unwrap().unwrap();
        assert!(matches!(start.work, Work::Start { .. }));
        let c = change(&s, &p);
        s.execute(
            &lead,
            &Command::Send(Direct {
                change: c,
                member_id: mid.clone(),
                body: "Do not lose this".into(),
            }),
        )
        .unwrap();
        assert!(s.next_effect().unwrap().is_none());
        s.record_run_admission(&start.effect_id, "run", 1).unwrap();
        s.bind_run(&start.effect_id, "native:exact").unwrap();
        let mut delivered = false;
        while let Some(e) = s.next_effect().unwrap() {
            if let Work::Deliver { address, text, .. } = e.work {
                assert_eq!(address, "native:exact");
                delivered |= text.contains("Do not lose this");
            }
        }
        assert!(delivered);
    }
    /// Twenty maximum-size assignments and quoted proposal data remain retrievable without skipping rows.
    #[test]
    fn maximum_content_fits_notifications_and_paginated_presentation() {
        let (_d, mut s) = fixture();
        let lead = actor("lead");
        let p = make(&mut s, &lead, "one");
        let a = actor("member0");
        for index in 0..MAX_MEMBERS {
            let c = change(&s, &p);
            s.execute(
                &lead,
                &Command::Add(Add {
                    change: c,
                    address: actor(&format!("member{index}")).address,
                    name: "\\".repeat(80),
                    role: "\\".repeat(160),
                    task: "\\".repeat(512),
                }),
            )
            .unwrap();
        }
        join(&mut s, &a, &p);
        let c = change(&s, &p);
        s.execute(
            &lead,
            &Command::Propose(Propose {
                change: c,
                result: "\\".repeat(MAX_TEXT),
                criteria: "\\".repeat(MAX_TEXT),
            }),
        )
        .unwrap();
        let templates = crate::response::Templates::new(&crate::tools::templates()).unwrap();
        for who in [&lead, &a] {
            for section in [
                Section::Overview,
                Section::Members,
                Section::History,
                Section::Proposal,
                Section::Votes,
                Section::Deliveries,
            ] {
                let mut cursor = 0;
                loop {
                    let reply = s
                        .execute(
                            who,
                            &Command::Get(Get {
                                pool_id: p.clone(),
                                after: cursor,
                                section: section.clone(),
                                proposal_id: None,
                            }),
                        )
                        .unwrap();
                    let view = match &reply {
                        Reply::View(v) | Reply::OwnerView { view: v, .. } => v,
                        _ => panic!("view"),
                    };
                    let more = view.has_more;
                    let next = view.next_after;
                    let result = crate::tools::present(Ok(reply), &templates);
                    let encoded = serde_json::to_value(result).unwrap();
                    let text = encoded["content"][0]["text"].as_str().unwrap();
                    assert!(!text.contains("presentation degraded"), "{text}");
                    assert!(text.len() <= 16384);
                    if !more {
                        break;
                    }
                    assert!(next > cursor);
                    cursor = next;
                }
            }
        }
    }
    /// A permanent unknown head cannot starve later custody work, and owner failures stay inspectable.
    #[test]
    fn reconciliation_rotates_and_owner_failures_do_not_recurse() {
        let (_d, mut s) = fixture();
        let lead = actor("lead");
        let p = make(&mut s, &lead, "one");
        for _ in 0..40 {
            queue_delivery(&s.db, &p, None, &lead.address, "owner", "test".into()).unwrap();
        }
        s.db.execute("UPDATE effects SET state='custody'", [])
            .unwrap();
        let first = s.pending_unknown().unwrap();
        let second = s.pending_unknown().unwrap();
        assert_eq!(first.len(), 32);
        assert_eq!(second.len(), 8);
        assert!(
            !first
                .iter()
                .any(|a| second.iter().any(|b| a.effect_id == b.effect_id))
        );
        let before = count(&s, "events");
        s.settle_effect(&first[0].effect_id, "refused").unwrap();
        assert_eq!(count(&s, "events"), before + 1);
        assert_eq!(count(&s, "effects"), 40);
        s.settle_effect(&first[1].effect_id, "refused").unwrap();
        assert_eq!(count(&s, "events"), before + 2);
    }
    /// Accepted decisions remain independently readable after a later proposal replaces the current one.
    #[test]
    fn accepted_decision_archive_is_immutable_and_scoped() {
        let (_d, mut s) = fixture();
        let lead = actor("lead");
        let a = actor("a");
        let p = make(&mut s, &lead, "one");
        add(&mut s, &lead, &p, &a);
        join(&mut s, &a, &p);
        let c = change(&s, &p);
        s.execute(
            &a,
            &Command::Propose(Propose {
                change: c,
                result: "First".into(),
                criteria: "Exact".into(),
            }),
        )
        .unwrap();
        let pr = pool(&s.db, &p).unwrap().0.proposal.unwrap();
        let c = change(&s, &p);
        s.execute(
            &a,
            &Command::Vote(Vote {
                change: c,
                proposal_id: pr.proposal_id.clone(),
                roster_key: pr.roster_key,
                choice: Choice::Ready,
                evidence: "proof".into(),
            }),
        )
        .unwrap();
        let c = change(&s, &p);
        s.execute(
            &a,
            &Command::Propose(Propose {
                change: c,
                result: "Second".into(),
                criteria: "New".into(),
            }),
        )
        .unwrap();
        let reply = s
            .execute(
                &a,
                &Command::Get(Get {
                    pool_id: p,
                    after: 0,
                    section: Section::Proposal,
                    proposal_id: Some(pr.proposal_id),
                }),
            )
            .unwrap();
        let Reply::View(v) = reply else {
            panic!("view")
        };
        let old = v.pool.proposal.unwrap();
        assert_eq!(old.state, ProposalState::Accepted);
        assert_eq!(old.result, "First");
    }
    /// A changed binding cannot join using an earlier provider precheck, even with a current revision.
    #[test]
    fn join_fence_rejects_changed_binding_before_committing() {
        let (_d, mut s) = fixture();
        let lead = actor("lead");
        let a = actor("a");
        let p = make(&mut s, &lead, "one");
        let mid = add(&mut s, &lead, &p, &a);
        let checked = s.join_binding(&a, &p).unwrap();
        let c = change(&s, &p);
        s.execute(
            &lead,
            &Command::MemberUpdate(MemberUpdate {
                change: c,
                member_id: mid.clone(),
                name: "Changed".into(),
                role: "Changed role".into(),
                task: "Changed task".into(),
            }),
        )
        .unwrap();
        let join = Command::Join(change(&s, &p));
        let events = count(&s, "events");
        assert!(matches!(
            s.execute_join(&a, &join, &checked),
            Err(Fault::Stale)
        ));
        assert_eq!(count(&s, "events"), events);
        assert_eq!(
            binding_any(&s.db, &mid).unwrap().0.member.state,
            MemberState::Pending
        );
        let checked = s.join_binding(&a, &p).unwrap();
        s.execute_join(&a, &join, &checked).unwrap();
        assert_eq!(
            binding_any(&s.db, &mid).unwrap().0.member.state,
            MemberState::Active
        );
    }
    /// A start provably cancelled before admission leaves no impossible final-notice delivery pending.
    #[test]
    fn removed_unadmitted_start_cancels_unresolvable_final_notice() {
        let (_d, mut s) = fixture();
        let lead = actor("lead");
        let p = make(&mut s, &lead, "one");
        let c = change(&s, &p);
        let reply=s.execute(&lead,&Command::Start(Start{change:c,name:"Pending".into(),role:"Test".into(),task:"Verify".into(),spec:serde_json::json!({"task":"Original","provider":"codex","model":"test","profile":"implement","workdir":"/known"})})).unwrap();
        let mid = match reply {
            Reply::Receipt(r) => r.created_id.unwrap(),
            _ => panic!("receipt"),
        };
        let effect = s.next_effect().unwrap().unwrap();
        let c = change(&s, &p);
        s.execute(
            &lead,
            &Command::Remove(Remove {
                change: c,
                member_id: mid.clone(),
            }),
        )
        .unwrap();
        let before: i64 =
            s.db.query_row(
                "SELECT count(*) FROM effects WHERE member=?1 AND state='awaiting_binding'",
                [&mid],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(before, 1);
        s.settle_effect(&effect.effect_id, "cancelled").unwrap();
        let after: i64 =
            s.db.query_row(
                "SELECT count(*) FROM effects WHERE member=?1 AND state='awaiting_binding'",
                [&mid],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(after, 0);
        while let Some(e) = s.next_effect().unwrap() {
            assert!(!matches!(e.work, Work::Deliver { .. }));
        }
    }
    /// Refusing a future database must leave its bytes and journal mode unchanged.
    #[test]
    fn future_schema_refuses_before_mutating_database() {
        let (d, s) = fixture();
        drop(s);
        let path = d.path().join("future.sqlite");
        let db = Connection::open(&path).unwrap();
        db.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA user_version=999; CREATE TABLE retained(value TEXT);").unwrap();
        drop(db);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let before = std::fs::read(&path).unwrap();
        assert!(matches!(Store::open(&path), Err(Fault::Conflict)));
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
    /// A confirmed lost execution wakes the owner without closing the pool or removing membership.
    #[test]
    fn lost_execution_is_actionable_without_claiming_process_exit() {
        let (_d, mut s) = fixture();
        let lead = actor("lead");
        let a = actor("a");
        let p = make(&mut s, &lead, "one");
        let mid = add(&mut s, &lead, &p, &a);
        join(&mut s, &a, &p);
        s.db.execute("UPDATE effects SET state='accepted'", [])
            .unwrap();
        s.observe_member(&p, &mid, "lost").unwrap();
        assert!(!pool(&s.db, &p).unwrap().0.closed);
        assert_eq!(bindings(&s.db, &p).unwrap()[0].member.runtime, "lost");
        let mut owner_notified = false;
        while let Some(e) = s.next_effect().unwrap() {
            if let Work::Deliver { address, text, .. } = e.work {
                owner_notified |= address == lead.address && text.contains("lost");
            }
        }
        assert!(owner_notified);
    }
    /// Typed flat wire arguments accept only their documented fields and preserve literal message data.
    #[test]
    fn flat_commands_are_strict_and_validate_unicode_bytes() {
        let value = serde_json::json!({"name":"pool_post","arguments":{"pool_id":"pool","expected_revision":1,"request_key":"key","body":"Привет {{literal}}"}});
        let c: Command = serde_json::from_value(value.clone()).unwrap();
        c.validate().unwrap();
        let mut invalid = value;
        invalid["arguments"]["actor_id"] = serde_json::json!("fake");
        assert!(serde_json::from_value::<Command>(invalid).is_err());
        assert!(text(&"я".repeat(MAX_TEXT), MAX_TEXT).is_err());
    }
}
