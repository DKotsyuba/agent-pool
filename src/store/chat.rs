//! Ordinary Run chat state, sharing the resident roster, journal and mutation receipts.
use super::*;
use crate::{
    chat::{Start, StartMember, *},
    integrations::BatchAdmission,
};
use bridge_sdk::bridge_protocol::NativeAddress;
use serde_json::{Value, json};

const OWNER: &str = "pool-chat-v1-owner";

/// Installs the chat discriminator, immutable batch inputs and agreement ledger.
pub(super) fn migrate(db: &Connection) -> Result<(), Fault> {
    db.execute_batch("
        CREATE TABLE IF NOT EXISTS chat_pools(pool TEXT PRIMARY KEY REFERENCES pools(id), owner_address TEXT);
        CREATE TABLE IF NOT EXISTS chat_batches(
            id TEXT PRIMARY KEY, pool TEXT NOT NULL REFERENCES chat_pools(pool),
            request_key TEXT NOT NULL, digest TEXT NOT NULL, jobs TEXT NOT NULL,
            old_agent_id TEXT, is_start INTEGER NOT NULL, run_store TEXT, state TEXT NOT NULL DEFAULT 'pending',
            closed_at_ms INTEGER, next_receipt_ms INTEGER NOT NULL DEFAULT 0,
            receipt_delay_ms INTEGER NOT NULL DEFAULT 5000,
            UNIQUE(pool, request_key, is_start));
        CREATE UNIQUE INDEX IF NOT EXISTS chat_pending_batch ON chat_batches(pool) WHERE state='pending';
        CREATE TABLE IF NOT EXISTS chat_notice_targets(effect TEXT PRIMARY KEY REFERENCES effects(id), member TEXT NOT NULL REFERENCES members(id));
        CREATE TABLE IF NOT EXISTS chat_agreements(
            pool TEXT PRIMARY KEY REFERENCES chat_pools(pool), id TEXT NOT NULL UNIQUE, data TEXT NOT NULL);
        CREATE TRIGGER IF NOT EXISTS chat_agreement_immutable BEFORE UPDATE ON chat_agreements BEGIN SELECT RAISE(ABORT,'chat agreement is immutable'); END;
        CREATE TRIGGER IF NOT EXISTS chat_agreement_retained BEFORE DELETE ON chat_agreements BEGIN SELECT RAISE(ABORT,'chat agreement is retained'); END;
        PRAGMA user_version=18;")?;
    let installed: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='inventory_rev_chat_pools_INSERT')",
        [],
        |r| r.get(0),
    )?;
    if !installed {
        inventory_revision_triggers(db, &["chat_pools", "chat_batches", "chat_agreements"])?;
    }
    Ok(())
}

/// Checks the mode without exposing routing metadata.
pub(crate) fn enabled(db: &Connection, pool: &str) -> Result<bool, Fault> {
    Ok(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM chat_pools WHERE pool=?1)",
        [pool],
        |r| r.get(0),
    )?)
}

/// Returns the optional owner destination for a chat-mode event.
pub(super) fn owner_address(db: &Connection, pool: &str) -> Result<Option<String>, Fault> {
    Ok(db.query_row(
        "SELECT owner_address FROM chat_pools WHERE pool=?1",
        [pool],
        |r| r.get(0),
    )?)
}

/// Reads a chat agreement by pool and optionally an exact agreement ID.
pub(super) fn agreement(
    db: &Connection,
    pool: &str,
    id: Option<&str>,
) -> Result<Option<Agreement>, Fault> {
    db.query_row(
        "SELECT data FROM chat_agreements WHERE pool=?1 AND (?2 IS NULL OR id=?2)",
        params![pool, id],
        |r| r.get::<_, String>(0),
    )
    .optional()?
    .map(|raw| decode(&raw))
    .transpose()
}

/// Final vote and its agreement, journal event, and notice share the mutation transaction.
pub(super) fn commit_agreement(
    db: &Connection,
    pool: &Pool,
    roster: &[Binding],
) -> Result<String, Fault> {
    let proposal = pool.proposal.as_ref().ok_or(Fault::Internal)?;
    let completion_id = id();
    let event = append_event(
        db,
        pool,
        "pool_completed",
        Author::Service,
        format!(
            "Agreement {completion_id} committed for proposal {}.",
            proposal.proposal_id
        ),
        None,
    )?;
    let mut ballots = Vec::with_capacity(roster.len());
    for binding in roster {
        let seat_id = &binding.member.member_id;
        let ballot = proposal.votes.get(seat_id).ok_or(Fault::Internal)?;
        ballots.push(AgreementBallot {
            seat_id: seat_id.clone(),
            agent_id: binding.run_id.clone().ok_or(Fault::Internal)?,
            vote_event_id: ballot.vote_event_id.clone().ok_or(Fault::Internal)?,
        });
    }
    let record = Agreement {
        version: 1,
        completion_id,
        pool_id: pool.pool_id.clone(),
        revision: pool.revision,
        event_id: event.event_id.to_string(),
        proposal_id: proposal.proposal_id.clone(),
        roster_key: proposal.roster_key.clone(),
        result: proposal.result.clone(),
        ballots,
    };
    db.execute(
        "INSERT INTO chat_agreements (pool,id,data) VALUES (?1,?2,?3)",
        params![record.pool_id, record.completion_id, encode(&record)?],
    )?;
    if let Some(address) = owner_address(db, &record.pool_id)? {
        queue_delivery(
            db,
            &record.pool_id,
            None,
            &address,
            &format!("owner:{}", record.pool_id),
            format!(
                "Pool {} completed. Agreement {}. Read pool_completion_get for the result.",
                record.pool_id, record.completion_id
            ),
            Some(event.event_id),
        )?;
    }
    Ok(record.completion_id)
}

/// Frozen ordered batch shared by receipt lookup and admission.
#[derive(Serialize, serde::Deserialize)]
pub(crate) struct ChatBatch {
    pub closed: bool,
    pub id: String,
    pub pool_id: String,
    pub request_key: String,
    pub jobs: Vec<BatchJob>,
    pub old_agent_id: Option<String>,
    pub run_store: Option<String>,
    pub state: String,
}

fn batch_by_key(
    db: &Connection,
    pool: Option<&str>,
    key: &str,
    digest: &str,
) -> Result<Option<ChatBatch>, Fault> {
    let previous: Option<(String, String)> = db.query_row(
        "SELECT id,digest FROM chat_batches WHERE request_key=?1 AND ((?2 IS NULL AND is_start=1) OR (pool=?2 AND is_start=0))",
        params![key, pool], |r| Ok((r.get(0)?,r.get(1)?))).optional()?;
    previous
        .map(|(id, previous_digest)| {
            if previous_digest != digest {
                return Err(Fault::Conflict);
            }
            batch_by_id(db, &id)
        })
        .transpose()
}

fn batch_by_id(db: &Connection, id: &str) -> Result<ChatBatch, Fault> {
    let (pool_id, jobs, old_agent_id, run_store, state, request_key): (String, String, _, _, _, _) = db.query_row(
        "SELECT pool,jobs,old_agent_id,run_store,state,request_key FROM chat_batches WHERE id=?1",
        [id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
    )?;
    Ok(ChatBatch {
        closed: pool(db, &pool_id)?.0.closed,
        id: id.into(),
        pool_id,
        request_key,
        jobs: decode(&jobs)?,
        old_agent_id,
        run_store,
        state,
    })
}

fn make_job(
    db: &Connection,
    pool: &Pool,
    member: StartMember,
    slot: &str,
) -> Result<BatchJob, Fault> {
    let StartMember {
        assignment,
        mut spec,
    } = member;
    let spec_map = spec.as_object_mut().ok_or(Fault::Invalid)?;
    if ["pool_chat", "request_id", "orchestrator"]
        .iter()
        .any(|f| spec_map.contains_key(*f))
    {
        return Err(Fault::Invalid);
    }
    for field in ["provider", "model", "profile", "workdir"] {
        text(
            spec_map
                .get(field)
                .and_then(Value::as_str)
                .ok_or(Fault::Invalid)?,
            4096,
        )?;
    }
    let role = spec_map
        .get("profile")
        .and_then(Value::as_str)
        .ok_or(Fault::Invalid)?;
    crate::domain::assignment(role, role, &assignment)?;
    let binding = new_binding(pool, role, role, &assignment, None);
    let seat = &binding.member.member_id;
    let store_id: String = db.query_row(
        "SELECT store_id FROM inventory_source WHERE singleton=1",
        [],
        |r| r.get(0),
    )?;
    let store_id = format!("store_{}", store_id.replace('-', ""));
    crate::domain::store_id(&store_id)?;
    let task = match spec_map.get("task") {
        Some(Value::String(task)) => task.as_str(),
        Some(_) => return Err(Fault::Invalid),
        None => &assignment,
    };
    let prompt = format!(
        "{task}\n\nPool {} seat {seat}. Assignment: {assignment}\nGoal: {}\nUse pool_get for the current revision, then pool_join. Use the Pool chat tools to coordinate and agree a result.",
        pool.pool_id, pool.purpose
    );
    spec_map.insert("task".into(), json!(prompt));
    spec_map.insert(
        "pool_chat".into(),
        json!({"version":1,"pool_id":pool.pool_id,"seat_id":seat,"pool_store_id":store_id}),
    );
    save_binding(db, &binding, true)?;
    db.execute(
        "INSERT INTO member_slots(member,slot) VALUES (?1,?2)",
        params![seat, slot],
    )?;
    Ok(BatchJob {
        member_id: seat.clone(),
        spec,
        original_spec: None,
    })
}

fn save_batch(
    db: &Connection,
    pool_id: &str,
    key: &str,
    digest: &str,
    jobs: Vec<BatchJob>,
    old_agent_id: Option<String>,
    is_replacement: bool,
) -> Result<ChatBatch, Fault> {
    let batch_id = format!("agent-pool.chat.{}", id());
    let payload = encode(&jobs)?;
    if payload.len() > crate::integrations::MAX_FRAME - 1024 {
        return Err(Fault::Invalid);
    }
    db.execute("INSERT INTO chat_batches(id,pool,request_key,digest,jobs,old_agent_id,is_start) VALUES (?1,?2,?3,?4,?5,?6,?7)",
        params![batch_id,pool_id,key,digest,payload,old_agent_id,!is_replacement])?;
    batch_by_id(db, &batch_id)
}

/// A single SQL transaction reserves the pool, ordered seats and exact Run batch.
pub(crate) fn start(store: &mut Store, input: Start) -> Result<ChatBatch, Fault> {
    let command = Command::Create(input.create.clone());
    command.validate()?;
    if !(1..=MAX_MEMBERS).contains(&input.members.len()) {
        return Err(Fault::Invalid);
    }
    if let Some(address) = &input.owner_address
        && !NativeAddress::parse(address).is_ok_and(|parsed| parsed.canonical() == *address)
    {
        return Err(Fault::Invalid);
    }
    let digest = format!("{:x}", Sha256::digest(encode(&input)?));
    let tx = store
        .db
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(batch) = batch_by_key(&tx, None, &input.create.request_key, &digest)? {
        return Ok(batch);
    }
    let Reply::Receipt(receipt) = create(&tx, &owner(), &input.create, &command)? else {
        return Err(Fault::Internal);
    };
    let (pool, _) = pool(&tx, &receipt.pool_id)?;
    tx.execute(
        "INSERT INTO chat_pools(pool,owner_address) VALUES (?1,?2)",
        params![pool.pool_id, input.owner_address],
    )?;
    let jobs = input
        .members
        .into_iter()
        .enumerate()
        .map(|(slot, member)| make_job(&tx, &pool, member, &format!("{slot:02}")))
        .collect::<Result<_, _>>()?;
    let batch = save_batch(
        &tx,
        &pool.pool_id,
        &input.create.request_key,
        &digest,
        jobs,
        None,
        false,
    )?;
    tx.commit()?;
    Ok(batch)
}

/// Replacement retires the previous seat and reserves a new incarnation and durable batch.
pub(crate) fn replace(store: &mut Store, input: ReplaceSeat) -> Result<ChatBatch, Fault> {
    let digest = format!("{:x}", Sha256::digest(encode(&input)?));
    let Change {
        pool_id,
        expected_revision,
        request_key,
    } = &input.change;
    identifier(request_key)?;
    identifier(pool_id)?;
    identifier(&input.member_id)?;
    let tx = store
        .db
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    if !enabled(&tx, pool_id)? {
        return Err(Fault::Forbidden);
    }
    if let Some(batch) = batch_by_key(&tx, Some(pool_id), request_key, &digest)? {
        return Ok(batch);
    }
    let (mut pool, _) = pool(&tx, pool_id)?;
    if pool.closed {
        return Err(Fault::Closed);
    }
    if agreement(&tx, pool_id, None)?.is_some() {
        return Err(Fault::Completed);
    }
    if pool.revision != *expected_revision {
        return Err(Fault::Stale);
    }
    if tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM chat_batches WHERE pool=?1 AND state='pending')",
        [pool_id],
        |r| r.get::<_, bool>(0),
    )? {
        return Err(Fault::Conflict);
    }
    let old = bindings(&tx, pool_id)?
        .into_iter()
        .find(|b| b.member.member_id == input.member_id)
        .ok_or(Fault::Forbidden)?;
    let prior = old.run_id.clone();
    let slot: String = tx.query_row(
        "SELECT slot FROM member_slots WHERE member=?1",
        [&input.member_id],
        |r| r.get(0),
    )?;
    save_binding(&tx, &old, false)?;
    let job = make_job(&tx, &pool, input.member, &slot)?;
    stale(&mut pool);
    pool.revision = pool.revision.checked_add(1).ok_or(Fault::Internal)?;
    save_pool(&tx, &pool)?;
    append_event(
        &tx,
        &pool,
        "seat_replaced",
        Author::Leader,
        format!("Seat {} replaced by {}.", input.member_id, job.member_id),
        None,
    )?;
    let batch = save_batch(&tx, pool_id, request_key, &digest, vec![job], prior, true)?;
    tx.commit()?;
    Ok(batch)
}

/// Freezes the Run database identity before a first possible submission.
pub(crate) fn fence(
    store: &mut Store,
    batch: &str,
    run_store_id: &str,
) -> Result<ChatBatch, Fault> {
    store.db.execute(
        "UPDATE chat_batches SET run_store=?2 WHERE id=?1 AND run_store IS NULL AND state='pending'",
        params![batch, run_store_id],
    )?;
    batch_by_id(&store.db, batch)
}

/// Installs a confirmed ordered Run receipt in one transaction.
pub(crate) fn admitted(
    store: &mut Store,
    batch: &ChatBatch,
    rows: Vec<BatchAdmission>,
) -> Result<(), Fault> {
    if rows.len() != batch.jobs.len() {
        return Err(Fault::Internal);
    }
    let tx = store
        .db
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    for (job, row) in batch.jobs.iter().zip(rows) {
        let (mut binding, current) = binding_any(&tx, &job.member_id)?;
        if binding.run_id.is_some() && binding.run_id.as_deref() != Some(&row.agent_id) {
            return Err(Fault::Conflict);
        }
        binding.run_id = Some(row.agent_id);
        binding.run_sequence = Some(row.sequence);
        binding.run_execution_ref = Some(row.execution_ref);
        binding.run_store_id = batch.run_store.clone();
        save_binding(&tx, &binding, current)?;
    }
    tx.execute(
        "UPDATE chat_batches SET state='admitted' WHERE id=?1",
        [&batch.id],
    )?;
    tx.commit()?;
    Ok(())
}

/// Settles never-sent work and timestamps possible sends for receipt-only recovery.
pub(super) fn close_batches(db: &Connection, pool: &str) -> Result<(), Fault> {
    db.execute("UPDATE chat_batches SET state=CASE WHEN run_store IS NULL THEN 'not_launched' ELSE state END, closed_at_ms=?2 WHERE pool=?1 AND state='pending'",params![pool,receipt_clock()?])?;
    Ok(())
}

/// Settles a pending batch with definitive Run evidence.
pub(crate) fn settle_batch(store: &mut Store, id: &str, state: &str) -> Result<(), Fault> {
    store.db.execute(
        "UPDATE chat_batches SET state=?2 WHERE id=?1 AND state='pending'",
        params![id, state],
    )?;
    Ok(())
}

/// Synthetic storage principal shared by all kernel-authorized owners.
fn owner() -> Actor {
    Actor {
        key: OWNER.into(),
        address: OWNER.into(),
    }
}

/// Checks the exact relay seat and Run lineage before executing or looking up a replay.
pub(crate) fn member(store: &mut Store, call: MemberCall) -> Result<ChatReply, ChatError> {
    let tx = store
        .db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(Fault::from)?;
    if !enabled(&tx, &call.pool_id)? {
        return Err(ChatError::NotMember);
    }
    let (pool, _) = pool(&tx, &call.pool_id)?;
    let Some(raw) = tx
        .query_row(
            "SELECT data FROM members WHERE id=?1 AND pool=?2",
            params![call.seat_id, call.pool_id],
            |r| r.get::<_, String>(0),
        )
        .optional()
        .map_err(Fault::from)?
    else {
        return Err(ChatError::NotMember);
    };
    let binding: Binding = decode(&raw)?;
    if binding.run_id.as_deref() != Some(&call.agent_id)
        || binding.run_store_id.as_deref() != Some(&call.run_store_id)
    {
        let pending = binding.member.state == MemberState::Pending && binding.run_id.is_none()
            && tx.query_row("SELECT EXISTS(SELECT 1 FROM chat_batches b, json_each(b.jobs) j WHERE b.pool=?1 AND b.state='pending' AND b.run_store=?2 AND json_extract(j.value,'$.member_id')=?3)",
                params![call.pool_id, call.run_store_id, call.seat_id], |row| row.get::<_, bool>(0)).map_err(Fault::from)?;
        return Err(if pending {
            ChatError::AdmissionPending
        } else {
            ChatError::NotMember
        });
    }
    if pool.closed {
        return Err(ChatError::PoolClosed);
    }
    if binding.member.state == MemberState::Removed {
        return Err(ChatError::SeatRetired);
    }
    let mut args = call.arguments;
    for key in [
        "run_store_id",
        "agent_id",
        "sequence",
        "seat_id",
        "actor",
        "author",
        "pool_store_id",
    ] {
        args.remove(key);
    }
    args.insert("pool_id".into(), json!(call.pool_id));
    let response = if call.tool == "pool_get" {
        get(&tx, parse(Value::Object(args))?, Some(&call.seat_id))?
    } else {
        args.insert("request_key".into(), json!(call.request_id));
        let command = command(&call.tool, Value::Object(args))?;
        let actor = Actor {
            key: call.seat_id.clone(),
            address: call.seat_id.clone(),
        };
        ChatReply::Existing(execute_authorized(
            &tx,
            &actor,
            &command,
            None,
            true,
            None,
            Some(ChatActor::Member(&call.seat_id)),
        )?)
    };
    tx.commit().map_err(Fault::from)?;
    Ok(response)
}

/// Runs owner chat commands or compatibility reads under the group authority.
pub(crate) fn owner_call(store: &mut Store, tool: &str, args: Value) -> Result<ChatReply, Fault> {
    match tool {
        "pool_get" => get(&store.db, parse(args)?, None),
        "pool_list" => list(&store.db, parse(args)?),
        "pool_completion_get" => completion(&store.db, parse(args)?),
        "pool_post" | "pool_send_member" | "pool_close" => {
            let command = command(tool, args)?;
            let pid = &command.change().ok_or(Fault::Invalid)?.pool_id;
            let tx = store
                .db
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            if !enabled(&tx, pid)? {
                return Err(Fault::Forbidden);
            }
            let reply = execute_authorized(
                &tx,
                &owner(),
                &command,
                None,
                true,
                None,
                Some(ChatActor::Owner),
            )?;
            tx.commit()?;
            Ok(ChatReply::Existing(reply))
        }
        _ => Err(Fault::Invalid),
    }
}

fn completion(db: &Connection, input: CompletionGet) -> Result<ChatReply, Fault> {
    identifier(&input.pool_id)?;
    if let Some(id) = &input.completion_id {
        identifier(id)?;
    }
    if let Some(agreement) = agreement(db, &input.pool_id, input.completion_id.as_deref())? {
        return Ok(ChatReply::Agreement(agreement));
    }
    let id = input
        .completion_id
        .or(db
            .query_row(
                "SELECT completion_id FROM completion_records WHERE pool=?1",
                [&input.pool_id],
                |r| r.get(0),
            )
            .optional()?)
        .ok_or(Fault::Forbidden)?;
    Ok(ChatReply::Legacy(Box::new(crate::completion::page(
        db,
        &crate::completion::GetRequest {
            pool_id: input.pool_id,
            completion_id: id,
            section: input.section,
            after: input.after,
            limit: 1,
        },
    )?)))
}

fn list(db: &Connection, input: ListPools) -> Result<ChatReply, Fault> {
    let after = input.after.unwrap_or_default();
    if !after.is_empty() {
        identifier(&after)?;
    }
    let mut stmt = db.prepare(
        "
        SELECT p.id,p.data,COALESCE(a.id,c.completion_id) FROM pools p
        LEFT JOIN chat_agreements a ON a.pool=p.id LEFT JOIN completion_records c ON c.pool=p.id
        WHERE p.id>?1 AND (?2 IS NULL OR ?2=CASE WHEN json_extract(p.data,'$.closed') THEN 'closed'
             WHEN a.id IS NOT NULL OR c.completion_id IS NOT NULL THEN 'completed' ELSE 'open' END)
        ORDER BY p.id LIMIT 11",
    )?;
    let rows = stmt.query_map(
        params![after, input.state.as_ref().map(PoolState::as_str)],
        |r| Ok((r.get::<_, String>(1)?, r.get::<_, Option<String>>(2)?)),
    )?;
    let mut pools = Vec::new();
    for row in rows {
        let (raw, completion) = row?;
        let pool: Pool = decode(&raw)?;
        pools.push(PoolRow {
            status: status(&pool, completion.is_some()),
            name: pool.name,
            id: pool.pool_id,
            completion,
        });
    }
    let more = pools.len() > 10;
    pools.truncate(10);
    let next = if more {
        pools.last().map(|p| p.id.clone())
    } else {
        None
    };
    Ok(ChatReply::List {
        returned: pools.len(),
        pools,
        next,
    })
}

fn status(pool: &Pool, complete: bool) -> &'static str {
    if pool.closed {
        "closed"
    } else if complete {
        "completed"
    } else {
        "open"
    }
}

/// Projects compact roster and proposal information or a privacy-filtered history page.
pub(crate) fn get(db: &Connection, input: GetPool, seat: Option<&str>) -> Result<ChatReply, Fault> {
    identifier(&input.pool_id)?;
    let (pool, _) = pool(db, &input.pool_id)?;
    if input
        .expected_revision
        .is_some_and(|revision| revision != pool.revision)
    {
        return Err(Fault::Stale);
    }
    if input.section == ChatSection::History {
        let after = match input.after.as_deref() {
            Some(cursor) => cursor
                .parse::<i64>()
                .ok()
                .filter(|n| *n >= 0 && n.to_string() == cursor)
                .ok_or(Fault::Invalid)?,
            None => 0,
        };
        let (page, more) = event_page(
            db,
            &input.pool_id,
            Some(after),
            i64::MAX,
            false,
            seat.map_or(HistoryAudience::Full, HistoryAudience::Member),
        )?;
        let events: Vec<_> = page
            .into_iter()
            .map(|event| ChatEvent {
                id: event.event_id.to_string(),
                kind: event.kind,
                author: match event.author {
                    Author::Leader => "owner".into(),
                    Author::Service => "service".into(),
                    Author::Member(id) => id,
                },
                recipient: event.recipient,
                body: event.body,
                message_event_id: event.message_event_id,
                part_index: event.part_index,
                part_count: event.part_count,
            })
            .collect();
        let next = events
            .last()
            .map_or_else(|| after.to_string(), |event| event.id.clone());
        return Ok(ChatReply::History {
            pool_id: input.pool_id,
            revision: pool.revision,
            events,
            more,
            next,
        });
    }
    if input.section != ChatSection::Overview {
        let section = match input.section {
            ChatSection::Members => Section::Members,
            ChatSection::Proposal => Section::Proposal,
            ChatSection::Votes => Section::Votes,
            ChatSection::Criteria => Section::Criteria,
            ChatSection::Content => Section::Content,
            _ => return Err(Fault::Invalid),
        };
        let roster = bindings(db, &input.pool_id)?;
        let after = input
            .after
            .as_deref()
            .map(str::parse::<u64>)
            .transpose()
            .map_err(|_| Fault::Invalid)?
            .unwrap_or(0);
        let query = Get {
            pool_id: input.pool_id,
            after,
            section,
            proposal_id: None,
            member_id: None,
            wait_seconds: 0.0,
            reverse: false,
            before: None,
            field: input.field,
            expected_revision: input.expected_revision,
        };
        Command::Get(query.clone()).validate()?;
        let mut reply = view(db, pool, roster, &query, false, HistoryAudience::Full)?;
        if enabled(db, &query.pool_id)?
            && let Reply::View(ref mut view) = reply
            && let Some(proposal) = &mut view.pool.proposal
        {
            for vote in proposal.votes.values_mut() {
                vote.validity = None;
            }
        }
        return Ok(ChatReply::Existing(reply));
    }
    if input.after.is_some() || input.field.is_some() {
        return Err(Fault::Invalid);
    }
    let completion = agreement(db, &input.pool_id, None)?
        .map(|r| r.completion_id)
        .or(db
            .query_row(
                "SELECT completion_id FROM completion_records WHERE pool=?1",
                [&input.pool_id],
                |r| r.get(0),
            )
            .optional()?);
    let roster = bindings(db,&input.pool_id)?.into_iter().map(|binding| {
        let admitted = binding.run_id.is_some();
        let admission = if admitted { "admitted".into() } else {
            db.query_row("SELECT b.state FROM chat_batches b,json_each(b.jobs) j WHERE b.pool=?1 AND json_extract(j.value,'$.member_id')=?2",
                params![input.pool_id,binding.member.member_id], |r| r.get::<_,String>(0)).optional()?.unwrap_or_else(|| "unavailable".into())
        };
        Ok(SeatRow { seat_id: binding.member.member_id, profile: binding.member.role, assignment: brief(&binding.member.task, 110),
            run_store_id: binding.run_store_id, sequence: binding.run_sequence, agent_id: binding.run_id,
            admitted: admission, joined: binding.member.state == MemberState::Active, process: "unknown".into() })
    }).collect::<Result<Vec<_>,Fault>>()?;
    let state = status(&pool, completion.is_some());
    let (ready, blocked) = pool
        .proposal
        .as_ref()
        .filter(|p| p.state != ProposalState::Stale)
        .map_or((0, 0), |proposal| {
            proposal
                .votes
                .values()
                .fold((0, 0), |(ready, blocked), ballot| {
                    match (&ballot.choice, ballot.checks_met) {
                        (Choice::Ready, Some(false)) | (Choice::Block, _) => (ready, blocked + 1),
                        (Choice::Ready, _) => (ready + 1, blocked),
                        _ => (ready, blocked),
                    }
                })
        });
    Ok(ChatReply::Overview(Overview {
        latest_admission: db
            .query_row(
                "SELECT CASE WHEN state='pending' AND closed_at_ms<=?2-900000
                    THEN 'launch unconfirmed (closed pool)' ELSE state END
                  FROM chat_batches WHERE pool=?1 ORDER BY rowid DESC LIMIT 1",
                params![input.pool_id, receipt_clock()?],
                |row| row.get(0),
            )
            .optional()?,
        pool_id: pool.pool_id,
        name: pool.name,
        purpose: brief(&pool.purpose, 600),
        revision: pool.revision,
        state,
        seat_count: roster.len(),
        roster,
        ready,
        blocked,
        completion,
        proposal: pool.proposal.map(|p| ProposalRow {
            id: p.proposal_id,
            roster_key: p.roster_key,
            state: p.state,
        }),
        acceptance: pool.acceptance.is_some(),
    }))
}

/// Builds an up-to-date launch summary for the caller, including any prior lineage to cancel.
pub(crate) fn launch_read(store: &Store, batch: &ChatBatch) -> Result<ChatReply, Fault> {
    let batch = batch_by_id(&store.db, &batch.id)?;
    let (pool, _) = pool(&store.db, &batch.pool_id)?;
    let mut seats = Vec::with_capacity(batch.jobs.len());
    for job in batch.jobs {
        let (binding, current) = binding_any(&store.db, &job.member_id)?;
        seats.push(LaunchSeat {
            id: job.member_id,
            agent_id: binding.run_id,
            current,
            joined: binding.member.state == MemberState::Active,
        });
    }
    Ok(ChatReply::Launch {
        pool_id: batch.pool_id,
        revision: pool.revision,
        state: batch.state,
        request_key: batch.request_key,
        seats,
        old_agent_id: batch.old_agent_id,
    })
}

/// Enqueues owner and optional member notices alongside the existing journal event.
pub(super) fn queue_chat_notices(
    db: &Connection,
    pool: &Pool,
    roster: &[Binding],
    event: &Event,
    owner_address: Option<&str>,
    caller: Option<&Binding>,
) -> Result<(), Fault> {
    let text = format!(
        "Pool {} event {} ({}).\n{}",
        pool.pool_id, event.event_id, event.kind, event.body
    );
    if event.kind == "owner_message" {
        if let Some(address) = owner_address {
            queue_delivery(
                db,
                &pool.pool_id,
                None,
                address,
                &format!("owner:{}", pool.pool_id),
                text,
                Some(event.event_id),
            )?;
        }
        return Ok(());
    }
    if !matches!(event.kind.as_str(), "message" | "direct_message") {
        return Ok(());
    }
    for binding in roster {
        let member = &binding.member.member_id;
        if caller.is_some_and(|caller| caller.member.member_id == *member)
            || event
                .recipient
                .as_ref()
                .is_some_and(|recipient| recipient != member)
            || binding.run_id.is_none()
        {
            continue;
        }
        let effect = queue(
            db,
            &pool.pool_id,
            None,
            Work::Deliver {
                address: "pool-chat-unresolved".into(),
                scope: scope(member),
                text: text.clone(),
            },
        )?;
        db.execute(
            "INSERT INTO chat_notice_targets(effect,member) VALUES (?1,?2)",
            params![effect, member],
        )?;
    }
    Ok(())
}

/// Identifies an ordinary member notice and returns its frozen publication or live target.
pub(crate) enum Notice {
    Legacy,
    Cancelled,
    Frozen(String, Value),
    Unresolved(Box<Binding>),
}

pub(crate) fn notice(store: &Store, effect: &str) -> Result<Notice, Fault> {
    let id: Option<String> = store
        .db
        .query_row(
            "SELECT member FROM chat_notice_targets WHERE effect=?1",
            [effect],
            |r| r.get(0),
        )
        .optional()?;
    let Some(id) = id else {
        return Ok(Notice::Legacy);
    };
    let prior: Option<(String, String)> = store
        .db
        .query_row(
            "SELECT producer,params FROM publications WHERE effect=?1",
            [effect],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if let Some((producer, params)) = prior {
        return Ok(Notice::Frozen(producer, decode(&params)?));
    }
    let (binding, current) = binding_any(&store.db, &id)?;
    Ok(if current {
        Notice::Unresolved(Box::new(binding))
    } else {
        Notice::Cancelled
    })
}

/// Picks a pending batch in stable rotating order. Only the resident dispatches these.
pub(crate) fn next_batch(store: &Store, after: &str) -> Result<Option<ChatBatch>, Fault> {
    let id: Option<String> = store
        .db
        .query_row(
            "SELECT id FROM chat_batches WHERE state='pending' AND next_receipt_ms<=?2 ORDER BY id<=?1,id LIMIT 1",
            params![after,receipt_clock()?],
            |row| row.get(0),
        )
        .optional()?;
    id.map(|id| batch_by_id(&store.db, &id)).transpose()
}

/// Exposes only the mode and durable result identity to the observer.
pub(super) fn pool_facts(db: &Connection, pool: &str) -> Result<crate::observer::PoolFacts, Fault> {
    use crate::observer::{PoolFacts, PoolKind};
    let kind = if enabled(db, pool)? {
        PoolKind::Chat
    } else {
        PoolKind::Managed
    };
    let completion_id = db.query_row(
        "SELECT id FROM chat_agreements WHERE pool=?1 UNION ALL SELECT completion_id FROM completion_records WHERE pool=?1",
        [pool], |row| row.get(0)
    ).optional()?;
    Ok(PoolFacts {
        kind,
        completion_id,
    })
}

/// Adds ordinary chat seat facts without exposing the private binding.
pub(super) fn project_seat(
    db: &Connection,
    facts: &crate::observer::PoolFacts,
    binding: &mut Binding,
) -> Result<(), Fault> {
    if !matches!(facts.kind, crate::observer::PoolKind::Chat) {
        return Ok(());
    }
    let admission = if binding.run_id.is_some() {
        "admitted".into()
    } else {
        db.query_row(
            "SELECT CASE WHEN b.state='pending' AND b.run_store IS NULL THEN 'pending'
                         WHEN b.state='refused' THEN 'refused' ELSE 'unknown' END
             FROM chat_batches b,json_each(b.jobs) j WHERE b.pool=?1 AND json_extract(j.value,'$.member_id')=?2",
            params![binding.pool_id, binding.member.member_id], |row| row.get::<_,String>(0)
        ).optional()?.unwrap_or_else(|| "unknown".into())
    };
    binding.member.chat_seat = Some(ChatSeat {
        seat_id: binding.member.member_id.clone(),
        run_agent_id: binding.run_id.clone(),
        profile: binding.member.role.clone(),
        admission,
        joined: binding.member.state == MemberState::Active,
    });
    Ok(())
}

/// Delays the next receipt lookup after a miss or an unavailable Run endpoint.
pub(crate) fn defer_receipt(store: &mut Store, id: &str) -> Result<(), Fault> {
    store.db.execute(
        "UPDATE chat_batches SET next_receipt_ms=?2+receipt_delay_ms,
            receipt_delay_ms=min(600000,2*receipt_delay_ms)
         WHERE id=?1 AND state='pending' AND closed_at_ms IS NOT NULL",
        params![id, receipt_clock()?],
    )?;
    Ok(())
}

/// SQLite stores receipt timestamps as signed millisecond integers.
fn receipt_clock() -> Result<i64, Fault> {
    i64::try_from(crate::observer::now()?).map_err(|_| Fault::Unavailable)
}
