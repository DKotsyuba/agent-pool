//! Durable failure notices and resume attempts for ordinary Run chat seats.

use super::chat::{owner_address, queue_chat_notices, queue_owner_notice};
use super::*;
use crate::chat_recovery::{Failure, Outcome, Seat};

/// Installs the chat opt-out and one recovery record per seat execution.
pub(super) fn migrate(db: &Connection) -> Result<(), Fault> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS chat_resume_disabled(
            pool TEXT PRIMARY KEY REFERENCES chat_pools(pool)
        );
        CREATE TABLE IF NOT EXISTS chat_recovery(
            member TEXT NOT NULL REFERENCES members(id),
            sequence INTEGER NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            request_id TEXT,
            next_ms INTEGER NOT NULL DEFAULT 0,
            stopped INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY(member,sequence)
        );
        PRAGMA user_version=21;",
    )?;
    Ok(())
}

/// Selects the next admitted current chat seat in a bounded rotating sweep.
pub(crate) fn next(store: &Store, after: &str) -> Result<Option<Seat>, Fault> {
    let row: Option<(String, String, bool)> = store.db.query_row(
        "SELECT m.data,b.jobs,d.pool IS NULL
         FROM members m JOIN chat_pools c ON c.pool=m.pool JOIN pools p ON p.id=m.pool
         LEFT JOIN chat_resume_disabled d ON d.pool=m.pool
         JOIN chat_batches b ON b.pool=m.pool AND b.state='admitted'
         WHERE m.id>?1 AND m.current=1 AND json_extract(p.data,'$.closed')=0
           AND NOT EXISTS (SELECT 1 FROM chat_agreements a WHERE a.pool=p.id)
           AND json_type(m.data,'$.run_id')='text'
           AND EXISTS (SELECT 1 FROM json_each(b.jobs) j WHERE json_extract(j.value,'$.member_id')=m.id)
         ORDER BY m.id LIMIT 1",
        [after],
        |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
    ).optional()?;
    let Some((binding, jobs, enabled)) = row else {
        return Ok(None);
    };
    let binding: Binding = decode(&binding)?;
    let jobs: Vec<BatchJob> = decode(&jobs)?;
    let spec = jobs
        .iter()
        .find(|j| j.member_id == binding.member.member_id)
        .ok_or(Fault::Internal)?;
    Ok(Some(Seat {
        provider: spec.spec["provider"]
            .as_str()
            .ok_or(Fault::Internal)?
            .into(),
        binding,
        enabled,
    }))
}

/// Finds the unique designated leader seat. Ambiguous or absent leaders route to the owner.
pub(crate) fn leader(store: &Store, seat: &Seat) -> Result<Option<Binding>, Fault> {
    let roster = bindings(&store.db, &seat.binding.pool_id)?;
    let mut leaders = roster
        .into_iter()
        .filter(|b| matches!(b.member.role.as_str(), "leader" | "pool-leader"));
    let Some(leader) = leaders.next() else {
        return Ok(None);
    };
    Ok((leaders.next().is_none()
        && leader.member.member_id != seat.id()
        && leader.run_store_id == seat.binding.run_store_id)
        .then_some(leader))
}

/// Checks the exact live membership incarnation and the open pool in one transaction.
fn current(db: &Connection, seat: &Seat) -> Result<Option<Pool>, Fault> {
    let (pool, _) = pool(db, &seat.binding.pool_id)?;
    if pool.closed || super::chat::agreement(db, &pool.pool_id, None)?.is_some() {
        return Ok(None);
    }
    let live = bindings(db, &pool.pool_id)?.into_iter().any(|b| {
        b.member.member_id == seat.id()
            && b.run_id == seat.binding.run_id
            && b.run_store_id == seat.binding.run_store_id
    });
    Ok(live.then_some(pool))
}

/// Appends shared history and routes the durable wake to the current leader or owner.
fn announce(
    db: &Connection,
    pool: &Pool,
    leader: Option<&str>,
    kind: &str,
    body: String,
) -> Result<(), Fault> {
    let roster = bindings(db, &pool.pool_id)?;
    let target = leader.and_then(|id| roster.iter().find(|b| b.member.member_id == id));
    let audience = target.map(|b| vec![b.member.member_id.clone()]);
    let event = append_addressed_event(db, pool, kind, Author::Service, body, None, audience)?;
    if target.is_some() {
        queue_chat_notices(db, pool, &roster, &event, None)?;
    } else if let Some(address) = owner_address(db, &pool.pool_id)? {
        queue_owner_notice(db, &pool.pool_id, &address, &event, None)?;
    }
    Ok(())
}

/// Loads a due failure without queuing a duplicate notice.
pub(crate) fn due(store: &Store, member: &str, sequence: u32, now: i64) -> Result<bool, Fault> {
    Ok(store
        .db
        .query_row(
            "SELECT stopped=0 AND next_ms<=?3 FROM chat_recovery WHERE member=?1 AND sequence=?2",
            params![member, sequence, now],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or(true))
}

/// Selects a prior unsettled send when Run already has a newer execution.
pub(crate) fn advanced(store: &Store, member: &str, sequence: u32) -> Result<Option<u32>, Fault> {
    Ok(store.db.query_row(
        "SELECT sequence FROM chat_recovery WHERE member=?1 AND sequence<?2 AND request_id IS NOT NULL ORDER BY sequence DESC LIMIT 1",
        params![member, sequence],
        |r| r.get(0),
    ).optional()?)
}

/// Journals the observed advance without attributing it to an interrupted request.
pub(crate) fn settle_advanced(
    store: &mut Store,
    seat: &Seat,
    leader: Option<&str>,
    prior: u32,
    latest: u32,
) -> Result<(), Fault> {
    let tx = store
        .db
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let Some(pool) = current(&tx, seat)? else {
        return Ok(());
    };
    if tx.execute(
        "UPDATE chat_recovery SET request_id=NULL,stopped=1 WHERE member=?1 AND sequence=?2 AND request_id IS NOT NULL",
        params![seat.id(), prior],
    )? == 1 {
        announce(&tx, &pool, leader, "member_resume_outcome", format!(
            "{} · execution {prior}. Run now reports execution {latest}. The prior resume receipt is unconfirmed. Pool stopped retrying execution {prior}.",
            seat.binding.member.name
        ))?;
    }
    tx.commit()?;
    Ok(())
}

/// Journals a newly observed failure and, with usable quota, claims an idempotent attempt.
/// Replaying a pending claim keeps the original key and attempt number across restart.
pub(crate) fn claim(
    store: &mut Store,
    seat: &Seat,
    failure: &Failure,
    leader: Option<&str>,
    settings: crate::chat_recovery::Decision,
) -> Result<Option<String>, Fault> {
    let tx = store
        .db
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let Some(pool) = current(&tx, seat)? else {
        return Ok(None);
    };
    let sequence = failure.sequence;
    if tx.execute(
        "INSERT OR IGNORE INTO chat_recovery(member,sequence) VALUES (?1,?2)",
        params![seat.id(), sequence],
    )? == 1
    {
        announce(
            &tx,
            &pool,
            leader,
            "member_execution_failed",
            failure.notice(seat, settings),
        )?;
    }
    let mut request = None;
    if settings.enabled && settings.recovered() {
        let (attempts, pending, due): (u8, Option<String>, bool) = tx.query_row(
            "SELECT attempts,request_id,stopped=0 AND next_ms<=?3 FROM chat_recovery WHERE member=?1 AND sequence=?2",
            params![seat.id(), sequence, settings.now_ms],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
        )?;
        if due && let Some(key) = pending {
            request = Some(key);
        } else if due && attempts < crate::chat_recovery::MAX_ATTEMPTS {
            let key = format!("pool-resume-{}", id());
            let attempt = attempts + 1;
            tx.execute(
                "UPDATE chat_recovery SET request_id=?3,attempts=?4 WHERE member=?1 AND sequence=?2",
                params![seat.id(), sequence, key, attempt],
            )?;
            announce(
                &tx,
                &pool,
                leader,
                "member_resume_attempt",
                format!(
                    "{}. Quota is usable. Pool is requesting resume (attempt {attempt}/{}).",
                    failure.label(seat),
                    crate::chat_recovery::MAX_ATTEMPTS
                ),
            )?;
            request = Some(key);
        }
    }
    tx.commit()?;
    Ok(request)
}

/// Records an attempt outcome and releases the claim. Cooling down schedules a new key.
pub(crate) fn settle(
    store: &mut Store,
    seat: &Seat,
    failure: &Failure,
    leader: Option<&str>,
    request: &str,
    outcome: Outcome,
    now_ms: i64,
) -> Result<(), Fault> {
    let tx = store
        .db
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (pool, _) = pool(&tx, &seat.binding.pool_id)?;
    let attempt: u8 = tx.query_row(
        "SELECT attempts FROM chat_recovery WHERE member=?1 AND sequence=?2 AND request_id=?3",
        params![seat.id(), failure.sequence, request],
        |r| r.get(0),
    )?;
    let (next, message) = outcome.next(attempt, now_ms);
    tx.execute(
        "UPDATE chat_recovery SET request_id=NULL,next_ms=?3,stopped=?4 WHERE member=?1 AND sequence=?2",
        params![seat.id(), failure.sequence, next.unwrap_or(0), next.is_none()],
    )?;
    announce(
        &tx,
        &pool,
        leader,
        "member_resume_outcome",
        format!("{}. {message}", failure.label(seat)),
    )?;
    tx.commit()?;
    Ok(())
}
