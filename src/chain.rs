use crate::config::Settings;
use crate::model::{
    AccountRef, AccountScope, AccountSnapshot, AccountState, Block, ChainEvent, ChainStatus,
    GenesisEvent, IdentityState, IdentityUpsertRequest, LedgerEntry, LoginObservedRequest,
    PaymentCaptureRequest, SubmitResult, TokenEntryType, TokenMutationRequest, TxEnvelope,
    now_rfc3339,
};
use anyhow::{Context, bail};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ValidatorKeyFile {
    validator_id: String,
    secret_key_hex: String,
    public_key_hex: String,
    created_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct BlockHeaderToSign<'a> {
    index: u64,
    chain_id: &'a str,
    ts: &'a str,
    previous_hash: &'a str,
    transactions_hash: &'a str,
    state_hash: &'a str,
    validator_id: &'a str,
    validator_public_key: &'a str,
}

#[derive(Clone, Debug, Default)]
struct Projection {
    accounts: BTreeMap<AccountRef, AccountState>,
    ledger: HashMap<String, Vec<LedgerEntry>>,
    processed_requests: HashSet<String>,
}

pub struct ChainRuntime {
    settings: Settings,
    blocks_path: PathBuf,
    validator: SigningKey,
    validator_public_key: VerifyingKey,
    projection: Projection,
    blocks: Vec<Block>,
}

impl ChainRuntime {
    pub fn load(settings: Settings) -> anyhow::Result<Self> {
        std::fs::create_dir_all(&settings.data_dir)
            .with_context(|| format!("failed to create '{}'", settings.data_dir.display()))?;
        let (validator, validator_public_key) = load_or_create_validator(
            &settings.validator_key_path,
            &settings.validator_id,
        )?;
        let blocks_path = settings.data_dir.join("blocks.jsonl");
        let mut runtime = Self {
            settings,
            blocks_path,
            validator,
            validator_public_key,
            projection: Projection::default(),
            blocks: Vec::new(),
        };
        runtime.load_blocks()?;
        if runtime.blocks.is_empty() {
            runtime.write_genesis()?;
        }
        Ok(runtime)
    }

    pub fn status(&self) -> ChainStatus {
        let head_hash = self
            .blocks
            .last()
            .map(|block| block.hash.clone())
            .unwrap_or_else(|| "GENESIS".to_string());
        ChainStatus {
            chain_id: self.settings.chain_id.clone(),
            height: self.blocks.len().saturating_sub(1) as u64,
            head_hash,
            validator_id: self.settings.validator_id.clone(),
            validator_public_key: hex::encode(self.validator_public_key.to_bytes()),
            account_count: self.projection.accounts.len(),
            auth_mode: self.settings.auth_mode().to_string(),
        }
    }

    pub fn list_blocks(&self, limit: usize) -> Vec<Block> {
        self.blocks
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect::<Vec<_>>()
    }

    pub fn block(&self, index: u64) -> Option<Block> {
        self.blocks.iter().find(|block| block.index == index).cloned()
    }

    pub fn account_snapshot(&self, account: &AccountRef) -> AccountSnapshot {
        snapshot_from_state(self.projection.accounts.get(account), account)
    }

    pub fn account_ledger(&self, account: &AccountRef, limit: usize) -> Vec<LedgerEntry> {
        self.projection
            .ledger
            .get(&account.key())
            .map(|entries| entries.iter().rev().take(limit).cloned().collect())
            .unwrap_or_default()
    }

    pub fn submit_identity(
        &mut self,
        actor_app: &str,
        request: IdentityUpsertRequest,
    ) -> anyhow::Result<SubmitResult> {
        let account = AccountRef::new(AccountScope::User, normalize_account_id(&request.user_id)?);
        let event = ChainEvent::IdentityUpsert(IdentityUpsertRequest {
            user_id: account.id.clone(),
            ..request
        });
        self.submit(actor_app, event, Some(account))
    }

    pub fn submit_login(
        &mut self,
        actor_app: &str,
        request: LoginObservedRequest,
    ) -> anyhow::Result<SubmitResult> {
        let account = AccountRef::new(AccountScope::User, normalize_account_id(&request.user_id)?);
        let event = ChainEvent::LoginObserved(LoginObservedRequest {
            user_id: account.id.clone(),
            system: request.system.trim().to_string(),
            ..request
        });
        self.submit(actor_app, event, Some(account))
    }

    pub fn submit_payment(
        &mut self,
        actor_app: &str,
        request: PaymentCaptureRequest,
    ) -> anyhow::Result<SubmitResult> {
        let account = AccountRef::new(AccountScope::User, normalize_account_id(&request.user_id)?);
        if request.tokens <= 0 {
            bail!("tokens must be positive")
        }
        let event = ChainEvent::PaymentCaptured(PaymentCaptureRequest {
            user_id: account.id.clone(),
            ..request
        });
        self.submit(actor_app, event, Some(account))
    }

    pub fn submit_token(
        &mut self,
        actor_app: &str,
        request: TokenMutationRequest,
    ) -> anyhow::Result<SubmitResult> {
        let account = AccountRef::new(
            request.account_scope,
            normalize_account_id(&request.account_id)?,
        );
        let event = ChainEvent::TokenMutation(TokenMutationRequest {
            account_id: account.id.clone(),
            ..request
        });
        self.submit(actor_app, event, Some(account))
    }

    fn submit(
        &mut self,
        actor_app: &str,
        event: ChainEvent,
        primary_account: Option<AccountRef>,
    ) -> anyhow::Result<SubmitResult> {
        let request_key = request_key_for(actor_app, event_request_id(&event));
        if let Some(request_key) = request_key {
            if self.projection.processed_requests.contains(&request_key) {
                let snapshot = primary_account
                    .as_ref()
                    .map(|account| self.account_snapshot(account));
                return Ok(SubmitResult {
                    duplicate: true,
                    tx_id: None,
                    block_index: self.blocks.last().map(|block| block.index).unwrap_or(0),
                    chain_height: self.blocks.len().saturating_sub(1) as u64,
                    head_hash: self
                        .blocks
                        .last()
                        .map(|block| block.hash.clone())
                        .unwrap_or_else(|| "GENESIS".to_string()),
                    snapshot,
                    entry: None,
                });
            }
        }

        let tx = TxEnvelope {
            tx_id: random_hex(16),
            request_id: event_request_id(&event).map(ToOwned::to_owned),
            ts: now_rfc3339(),
            actor_app: actor_app.to_string(),
            event,
        };
        let mut preview_projection = self.projection.clone();
        let preview = apply_event(&mut preview_projection, &tx, 0, "")?;
        let state_hash = compute_state_hash(&preview.projected.accounts)?;
        let previous_hash = self
            .blocks
            .last()
            .map(|block| block.hash.clone())
            .unwrap_or_else(|| "GENESIS".to_string());
        let index = self.blocks.len() as u64;
        let block = self.seal_block(index, previous_hash, state_hash, vec![tx.clone()])?;
        let mut projected = self.projection.clone();
        let apply = apply_event(&mut projected, &tx, block.index, &block.hash)?;
        projected = apply.projected;
        append_block(&self.blocks_path, &block)?;
        self.projection = projected;
        self.blocks.push(block.clone());

        Ok(SubmitResult {
            duplicate: false,
            tx_id: Some(tx.tx_id),
            block_index: block.index,
            chain_height: self.blocks.len().saturating_sub(1) as u64,
            head_hash: block.hash,
            snapshot: apply.snapshot,
            entry: apply.entry,
        })
    }

    fn seal_block(
        &self,
        index: u64,
        previous_hash: String,
        state_hash: String,
        transactions: Vec<TxEnvelope>,
    ) -> anyhow::Result<Block> {
        let ts = now_rfc3339();
        let transactions_hash = sha256_json(&transactions)?;
        let header = BlockHeaderToSign {
            index,
            chain_id: &self.settings.chain_id,
            ts: &ts,
            previous_hash: &previous_hash,
            transactions_hash: &transactions_hash,
            state_hash: &state_hash,
            validator_id: &self.settings.validator_id,
            validator_public_key: &hex::encode(self.validator_public_key.to_bytes()),
        };
        let header_bytes = serde_json::to_vec(&header).context("failed to serialize block header")?;
        let signature_hex = hex::encode(self.validator.sign(&header_bytes).to_bytes());
        let hash = sha256_json(&json!({
            "header": header,
            "signature_hex": signature_hex,
        }))?;

        Ok(Block {
            index,
            chain_id: self.settings.chain_id.clone(),
            ts,
            previous_hash,
            transactions_hash,
            state_hash,
            validator_id: self.settings.validator_id.clone(),
            validator_public_key: hex::encode(self.validator_public_key.to_bytes()),
            signature_hex,
            hash,
            transactions,
        })
    }

    fn load_blocks(&mut self) -> anyhow::Result<()> {
        if !self.blocks_path.exists() {
            return Ok(());
        }
        let file = File::open(&self.blocks_path)
            .with_context(|| format!("failed to open '{}'", self.blocks_path.display()))?;
        let reader = BufReader::new(file);
        let mut projection = Projection::default();
        let mut blocks = Vec::new();
        for (idx, line) in reader.lines().enumerate() {
            let line = line.with_context(|| format!("failed reading block line {}", idx + 1))?;
            if line.trim().is_empty() {
                continue;
            }
            let block: Block = serde_json::from_str(&line)
                .with_context(|| format!("invalid block json at line {}", idx + 1))?;
            verify_block(
                &block,
                blocks.last().map(|item: &Block| item.hash.as_str()),
                &self.settings.chain_id,
                &self.validator_public_key,
            )?;
            for tx in &block.transactions {
                let applied = apply_event(&mut projection, tx, block.index, &block.hash)?;
                projection = applied.projected;
            }
            let expected_state_hash = compute_state_hash(&projection.accounts)?;
            if expected_state_hash != block.state_hash {
                bail!(
                    "state hash mismatch at block {}: expected {}, found {}",
                    block.index,
                    expected_state_hash,
                    block.state_hash
                );
            }
            blocks.push(block);
        }
        self.projection = projection;
        self.blocks = blocks;
        Ok(())
    }

    fn write_genesis(&mut self) -> anyhow::Result<()> {
        let tx = TxEnvelope {
            tx_id: random_hex(16),
            request_id: Some("genesis".to_string()),
            ts: now_rfc3339(),
            actor_app: "system".to_string(),
            event: ChainEvent::Genesis(GenesisEvent {
                chain_id: self.settings.chain_id.clone(),
                validator_id: self.settings.validator_id.clone(),
                validator_public_key: hex::encode(self.validator_public_key.to_bytes()),
            }),
        };
        let state_hash = compute_state_hash(&self.projection.accounts)?;
        let block = self.seal_block(0, "GENESIS".to_string(), state_hash, vec![tx.clone()])?;
        let applied = apply_event(&mut self.projection, &tx, block.index, &block.hash)?;
        self.projection = applied.projected;
        append_block(&self.blocks_path, &block)?;
        self.blocks.push(block);
        Ok(())
    }
}

struct AppliedEvent {
    projected: Projection,
    snapshot: Option<AccountSnapshot>,
    entry: Option<LedgerEntry>,
}

fn apply_event(
    projection: &mut Projection,
    tx: &TxEnvelope,
    block_index: u64,
    block_hash: &str,
) -> anyhow::Result<AppliedEvent> {
    let mut next = projection.clone();
    let request_key = request_key_for(&tx.actor_app, tx.request_id.as_deref());
    if let Some(request_key) = request_key.as_ref() {
        if next.processed_requests.contains(request_key) {
            bail!("request_id '{}' already processed", request_key);
        }
    }

    let mut snapshot = None;
    let mut entry = None;
    match &tx.event {
        ChainEvent::Genesis(_) => {}
        ChainEvent::IdentityUpsert(event) => {
            let account = AccountRef::new(AccountScope::User, normalize_account_id(&event.user_id)?);
            let state = next
                .accounts
                .entry(account.clone())
                .or_insert_with(|| AccountState::new(&account));
            let now = tx.ts.clone();
            update_identity(
                &mut state.identity,
                event.role.clone(),
                event.email.clone(),
                event.provider.clone(),
                event.subject.clone(),
                false,
                None,
                Some(&event.meta),
                &now,
            );
            state.updated_at = Some(now);
            snapshot = Some(snapshot_from_state(next.accounts.get(&account), &account));
        }
        ChainEvent::LoginObserved(event) => {
            let account = AccountRef::new(AccountScope::User, normalize_account_id(&event.user_id)?);
            let state = next
                .accounts
                .entry(account.clone())
                .or_insert_with(|| AccountState::new(&account));
            let now = tx.ts.clone();
            update_identity(
                &mut state.identity,
                None,
                None,
                Some(event.auth_mode.clone().unwrap_or_else(|| "session".to_string())),
                event.session_id.clone(),
                true,
                Some(event.system.clone()),
                Some(&event.meta),
                &now,
            );
            state.updated_at = Some(now);
            snapshot = Some(snapshot_from_state(next.accounts.get(&account), &account));
        }
        ChainEvent::PaymentCaptured(event) => {
            let account = AccountRef::new(AccountScope::User, normalize_account_id(&event.user_id)?);
            let state = next
                .accounts
                .entry(account.clone())
                .or_insert_with(|| AccountState::new(&account));
            let meta = enrich_payment_meta(&event.meta, event);
            let record = apply_token_transition(
                state,
                &account,
                tx,
                block_index,
                block_hash,
                TokenEntryType::Topup,
                event.tokens,
                meta,
            );
            next.ledger.entry(account.key()).or_default().push(record.clone());
            snapshot = Some(snapshot_from_state(next.accounts.get(&account), &account));
            entry = Some(record);
        }
        ChainEvent::TokenMutation(event) => {
            let account = AccountRef::new(event.account_scope, normalize_account_id(&event.account_id)?);
            let state = next
                .accounts
                .entry(account.clone())
                .or_insert_with(|| AccountState::new(&account));
            let record = apply_token_transition(
                state,
                &account,
                tx,
                block_index,
                block_hash,
                event.entry_type,
                event.delta,
                event.meta.clone(),
            );
            next.ledger.entry(account.key()).or_default().push(record.clone());
            snapshot = Some(snapshot_from_state(next.accounts.get(&account), &account));
            entry = Some(record);
        }
    }

    if let Some(request_key) = request_key {
        next.processed_requests.insert(request_key);
    }

    Ok(AppliedEvent {
        projected: next,
        snapshot,
        entry,
    })
}

fn update_identity(
    identity: &mut IdentityState,
    role: Option<String>,
    email: Option<String>,
    provider: Option<String>,
    subject: Option<String>,
    is_login: bool,
    system: Option<String>,
    meta: Option<&Value>,
    now: &str,
) {
    if let Some(role) = role.filter(|value| !value.trim().is_empty()) {
        identity.role = Some(role);
    }
    if let Some(meta_map) = meta.and_then(Value::as_object) {
        if let Some(groups) = meta_map.get("groups") {
            identity.groups = normalize_identity_groups(groups);
        }
        if let Some(active_team) = meta_map.get("active_team") {
            identity.active_team = normalize_active_team(active_team);
        }
        if let Some(team_count) = meta_map
            .get("team_count")
            .and_then(json_value_as_u64)
        {
            identity.team_count = team_count;
        }
        if let Some(pending_invitation_count) = meta_map
            .get("pending_invitation_count")
            .and_then(json_value_as_u64)
        {
            identity.pending_invitation_count = pending_invitation_count;
        }
    }
    if let Some(email) = email.filter(|value| !value.trim().is_empty()) {
        identity.email = Some(email);
    }
    if let Some(provider) = provider.filter(|value| !value.trim().is_empty()) {
        identity.provider = Some(provider);
    }
    if let Some(subject) = subject.filter(|value| !value.trim().is_empty()) {
        identity.subject = Some(subject);
    }
    if is_login {
        identity.last_login_at = Some(now.to_string());
        identity.last_login_system = system;
        identity.login_count = identity.login_count.saturating_add(1);
    }
    identity.updated_at = Some(now.to_string());
}

fn normalize_identity_groups(value: &Value) -> Vec<String> {
    let mut groups = Vec::new();
    let mut push_group = |candidate: &str| {
        let cleaned = candidate.trim().to_ascii_lowercase();
        if cleaned.is_empty() || groups.iter().any(|existing| existing == &cleaned) {
            return;
        }
        groups.push(cleaned);
    };
    match value {
        Value::String(raw) => {
            for item in raw.split(',') {
                push_group(item);
            }
        }
        Value::Array(items) => {
            for item in items {
                match item {
                    Value::String(raw) => push_group(raw),
                    other => push_group(&other.to_string()),
                }
            }
        }
        _ => {}
    }
    groups
}

fn normalize_active_team(value: &Value) -> Option<Value> {
    match value {
        Value::Object(map) => {
            let team_id = map
                .get("team_id")
                .and_then(Value::as_str)
                .or_else(|| map.get("id").and_then(Value::as_str))
                .map(str::trim)
                .filter(|candidate| !candidate.is_empty())?;
            let mut normalized = map.clone();
            normalized.insert("team_id".to_string(), Value::String(team_id.to_string()));
            Some(Value::Object(normalized))
        }
        Value::String(raw) => {
            let team_id = raw.trim();
            if team_id.is_empty() {
                None
            } else {
                Some(serde_json::json!({ "team_id": team_id }))
            }
        }
        _ => None,
    }
}

fn json_value_as_u64(value: &Value) -> Option<u64> {
    match value {
        Value::Number(number) => number.as_u64(),
        Value::String(raw) => raw.trim().parse::<u64>().ok(),
        _ => None,
    }
}

fn enrich_payment_meta(meta: &Value, event: &PaymentCaptureRequest) -> Value {
    let mut map = ensure_object(meta);
    map.entry("tokens".to_string())
        .or_insert_with(|| Value::from(event.tokens));
    if let Some(amount_minor) = event.amount_minor {
        map.insert("amount_minor".to_string(), Value::from(amount_minor));
    }
    if let Some(currency) = event.currency.as_ref().filter(|value| !value.trim().is_empty()) {
        map.insert("currency".to_string(), Value::String(currency.clone()));
    }
    if let Some(provider) = event.provider.as_ref().filter(|value| !value.trim().is_empty()) {
        map.insert("payment_provider".to_string(), Value::String(provider.clone()));
    }
    if let Some(payment_id) = event.payment_id.as_ref().filter(|value| !value.trim().is_empty()) {
        map.insert("payment_id".to_string(), Value::String(payment_id.clone()));
    }
    if let Some(checkout_flow) = event
        .checkout_flow
        .as_ref()
        .filter(|value| !value.trim().is_empty())
    {
        map.insert("checkout_flow".to_string(), Value::String(checkout_flow.clone()));
    }
    Value::Object(map)
}

fn apply_token_transition(
    state: &mut AccountState,
    account: &AccountRef,
    tx: &TxEnvelope,
    block_index: u64,
    block_hash: &str,
    entry_type: TokenEntryType,
    delta: i64,
    meta: Value,
) -> LedgerEntry {
    let mut meta = ensure_object(&meta);
    let mut requested_delta = delta;
    let mut new_paid = state.paid_balance;
    let mut new_free = state.free_balance;
    let mut shortfall = 0i64;

    match entry_type {
        TokenEntryType::Topup | TokenEntryType::Refund => {
            if requested_delta > 0 {
                new_paid += requested_delta;
            } else {
                requested_delta = 0;
            }
        }
        TokenEntryType::Grant => {
            if requested_delta > 0 {
                new_free += requested_delta;
            } else {
                requested_delta = 0;
            }
        }
        TokenEntryType::Cashout => {
            if requested_delta >= 0 {
                requested_delta = -requested_delta.abs();
            }
            let desired = requested_delta.abs();
            let paid_used = new_paid.min(desired);
            new_paid -= paid_used;
            shortfall = desired - paid_used;
            if shortfall > 0 {
                meta.insert("shortfall".to_string(), Value::from(shortfall));
            }
            meta.insert("paid_used".to_string(), Value::from(paid_used));
            meta.insert("free_used".to_string(), Value::from(0));
            meta.insert("used_total".to_string(), Value::from(paid_used));
            requested_delta = -paid_used;
        }
        TokenEntryType::Debit => {
            if requested_delta >= 0 {
                requested_delta = -requested_delta.abs();
            }
            let desired = requested_delta.abs();
            let free_used = new_free.min(desired);
            new_free -= free_used;
            let remaining = desired - free_used;
            let paid_used = new_paid.min(remaining);
            new_paid -= paid_used;
            shortfall = remaining - paid_used;
            if shortfall > 0 {
                meta.insert("shortfall".to_string(), Value::from(shortfall));
            }
            meta.insert("free_used".to_string(), Value::from(free_used));
            meta.insert("paid_used".to_string(), Value::from(paid_used));
            meta.insert("used_total".to_string(), Value::from(free_used + paid_used));
            requested_delta = -(free_used + paid_used);
        }
        TokenEntryType::Reserve => {
            let reservation_key = reservation_key(&meta, tx.request_id.as_deref(), &tx.tx_id);
            let requested = as_i64(meta.get("reserved")).unwrap_or_else(|| requested_delta.abs());
            let amount = requested.max(0);
            let entry = state.reservations.entry(reservation_key).or_insert(0);
            *entry += amount;
            state.reserved = state.reservations.values().copied().sum();
            requested_delta = 0;
            meta.insert("reserved".to_string(), Value::from(amount));
        }
        TokenEntryType::Release => {
            let reservation_key = reservation_key(&meta, tx.request_id.as_deref(), &tx.tx_id);
            let requested = as_i64(meta.get("reserved")).unwrap_or_else(|| requested_delta.abs());
            let amount = requested.max(0);
            if let Some(entry) = state.reservations.get_mut(&reservation_key) {
                *entry -= amount;
                if *entry <= 0 {
                    state.reservations.remove(&reservation_key);
                }
            }
            state.reserved = state.reservations.values().copied().sum();
            requested_delta = 0;
            meta.insert("reserved".to_string(), Value::from(amount));
        }
        TokenEntryType::Sync => {
            let balance = state.paid_balance + state.free_balance;
            let target_paid = as_i64(meta.get("target_paid_balance"));
            let target_free = as_i64(meta.get("target_free_balance"));
            let target_balance = as_i64(meta.get("target_balance")).unwrap_or(balance + requested_delta);
            if target_paid.is_some() || target_free.is_some() {
                if let Some(target_paid) = target_paid {
                    new_paid = target_paid.max(0);
                }
                if let Some(target_free) = target_free {
                    new_free = target_free.max(0);
                }
            } else {
                let target_balance = target_balance.max(0);
                if target_balance >= new_free {
                    new_paid = target_balance - new_free;
                } else {
                    new_free = target_balance;
                    new_paid = 0;
                }
            }
            requested_delta = (new_paid + new_free) - balance;
        }
        TokenEntryType::Adjust => {}
    }

    let final_type = if requested_delta == 0
        && !matches!(entry_type, TokenEntryType::Reserve | TokenEntryType::Release | TokenEntryType::Sync)
    {
        TokenEntryType::Adjust
    } else {
        entry_type
    };

    let balance_after = (new_paid + new_free).max(0);
    state.paid_balance = new_paid.max(0);
    state.free_balance = new_free.max(0);
    state.balance = balance_after;
    state.updated_at = Some(tx.ts.clone());

    meta.insert("paid_after".to_string(), Value::from(state.paid_balance));
    meta.insert("free_after".to_string(), Value::from(state.free_balance));
    if matches!(entry_type, TokenEntryType::Topup) {
        let tokens = as_i64(meta.get("tokens")).unwrap_or_else(|| requested_delta.abs());
        state.last_topup_tokens = tokens;
        state.last_topup_at = Some(tx.ts.clone());
    }
    if matches!(entry_type, TokenEntryType::Sync) {
        if let Some(capacity) = as_i64(meta.get("capacity")) {
            state.last_topup_tokens = capacity;
            state.last_topup_at = Some(
                meta.get("capacity_ts")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
                    .unwrap_or_else(|| tx.ts.clone()),
            );
        }
    }
    if matches!(entry_type, TokenEntryType::Debit) {
        state.spent_total += as_i64(meta.get("used_total")).unwrap_or(requested_delta.abs());
        state.shortfall_total += shortfall;
    }
    if matches!(entry_type, TokenEntryType::Cashout) {
        state.cashout_total += requested_delta.abs();
    }
    if matches!(entry_type, TokenEntryType::Grant) {
        state.free_grant_total += requested_delta.abs();
    }
    state.reserved = state.reservations.values().copied().sum();

    LedgerEntry {
        tx_id: tx.tx_id.clone(),
        request_id: tx.request_id.clone(),
        block_index,
        block_hash: block_hash.to_string(),
        ts: tx.ts.clone(),
        account_scope: account.scope,
        account_id: account.id.clone(),
        entry_type: final_type.to_string(),
        delta: requested_delta,
        balance_after: state.balance,
        paid_after: state.paid_balance,
        free_after: state.free_balance,
        reserved_after: state.reserved,
        shortfall,
        actor_app: tx.actor_app.clone(),
        meta: Value::Object(meta),
    }
}

fn snapshot_from_state(state: Option<&AccountState>, account: &AccountRef) -> AccountSnapshot {
    let fallback;
    let state = match state {
        Some(state) => state,
        None => {
            fallback = AccountState::new(account);
            &fallback
        }
    };
    let balance = state.balance;
    let capacity = state.last_topup_tokens.max(balance);
    let display_capacity = 1.max(capacity).max(balance);
    let low_threshold = if capacity > 0 {
        ((capacity as f64) * 0.2).round() as i64
    } else {
        0
    };
    let status = if capacity > 0 && balance <= low_threshold {
        "low"
    } else {
        "ok"
    };
    let identity = if account.scope == AccountScope::User {
        Some(state.identity.clone())
    } else {
        None
    };
    AccountSnapshot {
        scope: account.scope,
        account_id: account.id.clone(),
        balance,
        tokens: balance,
        paid_balance: state.paid_balance,
        free_balance: state.free_balance,
        reserved: state.reserved,
        available: (balance - state.reserved).max(0),
        in_use: 0,
        last_topup_tokens: state.last_topup_tokens,
        capacity,
        display_capacity,
        low_threshold,
        status: status.to_string(),
        last_topup_at: state.last_topup_at.clone(),
        updated_at: state.updated_at.clone(),
        spent_total: state.spent_total,
        cashout_total: state.cashout_total,
        shortfall_total: state.shortfall_total,
        free_grant_total: state.free_grant_total,
        identity,
    }
}

fn append_block(path: &Path, block: &Block) -> anyhow::Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("failed to append '{}'", path.display()))?;
    let line = serde_json::to_string(block).context("failed to serialize block")?;
    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")?;
    file.flush()?;
    Ok(())
}

fn verify_block(
    block: &Block,
    previous_hash: Option<&str>,
    chain_id: &str,
    validator_public_key: &VerifyingKey,
) -> anyhow::Result<()> {
    if block.chain_id != chain_id {
        bail!("unexpected chain id '{}'", block.chain_id);
    }
    let expected_previous = previous_hash.unwrap_or("GENESIS");
    if block.previous_hash != expected_previous {
        bail!(
            "block {} previous hash mismatch: expected {}, found {}",
            block.index,
            expected_previous,
            block.previous_hash
        );
    }
    if block.validator_public_key != hex::encode(validator_public_key.to_bytes()) {
        bail!("unexpected validator public key at block {}", block.index);
    }
    let expected_tx_hash = sha256_json(&block.transactions)?;
    if expected_tx_hash != block.transactions_hash {
        bail!("transactions hash mismatch at block {}", block.index);
    }
    let header = BlockHeaderToSign {
        index: block.index,
        chain_id: &block.chain_id,
        ts: &block.ts,
        previous_hash: &block.previous_hash,
        transactions_hash: &block.transactions_hash,
        state_hash: &block.state_hash,
        validator_id: &block.validator_id,
        validator_public_key: &block.validator_public_key,
    };
    let header_bytes = serde_json::to_vec(&header)?;
    let signature_bytes: [u8; 64] = hex::decode(&block.signature_hex)
        .context("invalid signature hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid signature length"))?;
    let signature = Signature::from_bytes(&signature_bytes);
    validator_public_key
        .verify(&header_bytes, &signature)
        .context("block signature verification failed")?;
    let expected_hash = sha256_json(&json!({
        "header": header,
        "signature_hex": block.signature_hex,
    }))?;
    if expected_hash != block.hash {
        bail!("block hash mismatch at block {}", block.index);
    }
    Ok(())
}

fn load_or_create_validator(path: &Path, validator_id: &str) -> anyhow::Result<(SigningKey, VerifyingKey)> {
    if path.exists() {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read validator file '{}'", path.display()))?;
        let keyfile: ValidatorKeyFile = serde_json::from_str(&raw)
            .with_context(|| format!("invalid validator file '{}'", path.display()))?;
        let secret_bytes: [u8; 32] = hex::decode(keyfile.secret_key_hex)
            .context("invalid validator secret key hex")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("validator secret key must be 32 bytes"))?;
        let validator = SigningKey::from_bytes(&secret_bytes);
        let verifying = validator.verifying_key();
        return Ok((validator, verifying));
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create '{}'", parent.display()))?;
    }
    let mut secret_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret_bytes);
    let validator = SigningKey::from_bytes(&secret_bytes);
    let verifying = validator.verifying_key();
    let keyfile = ValidatorKeyFile {
        validator_id: validator_id.to_string(),
        secret_key_hex: hex::encode(secret_bytes),
        public_key_hex: hex::encode(verifying.to_bytes()),
        created_at: now_rfc3339(),
    };
    let payload = serde_json::to_string_pretty(&keyfile)?;
    std::fs::write(path, payload)
        .with_context(|| format!("failed to write validator file '{}'", path.display()))?;
    Ok((validator, verifying))
}

fn compute_state_hash(accounts: &BTreeMap<AccountRef, AccountState>) -> anyhow::Result<String> {
    let stable_accounts = accounts
        .iter()
        .map(|(account, state)| {
            json!({
                "scope": account.scope,
                "account_id": account.id,
                "state": state,
            })
        })
        .collect::<Vec<_>>();
    sha256_json(&stable_accounts)
}

fn sha256_json<T: Serialize>(value: &T) -> anyhow::Result<String> {
    let bytes = serde_json::to_vec(value).context("failed to serialize value for hashing")?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(hex::encode(hasher.finalize()))
}

fn random_hex(bytes: usize) -> String {
    let mut raw = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut raw);
    hex::encode(raw)
}

fn normalize_account_id(value: &str) -> anyhow::Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("account id is required");
    }
    Ok(trimmed.to_string())
}

fn request_key_for(actor_app: &str, request_id: Option<&str>) -> Option<String> {
    request_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|request_id| format!("{}:{}", actor_app.trim(), request_id))
}

fn event_request_id(event: &ChainEvent) -> Option<&str> {
    match event {
        ChainEvent::Genesis(_) => Some("genesis"),
        ChainEvent::IdentityUpsert(event) => event.request_id.as_deref(),
        ChainEvent::LoginObserved(event) => event.request_id.as_deref(),
        ChainEvent::PaymentCaptured(event) => event.request_id.as_deref(),
        ChainEvent::TokenMutation(event) => event.request_id.as_deref(),
    }
}

fn ensure_object(value: &Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map.clone(),
        _ => Map::new(),
    }
}

fn as_i64(value: Option<&Value>) -> Option<i64> {
    let value = value?;
    if let Some(v) = value.as_i64() {
        return Some(v);
    }
    if let Some(v) = value.as_u64() {
        return Some(v as i64);
    }
    value.as_str().and_then(|raw| raw.trim().parse::<i64>().ok())
}

fn reservation_key(meta: &Map<String, Value>, request_id: Option<&str>, tx_id: &str) -> String {
    meta.get("reservation_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| {
            meta.get("job_id")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
        })
        .or_else(|| {
            request_id
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
        })
        .unwrap_or_else(|| tx_id.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AccountScope, TokenMutationRequest};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_settings() -> Settings {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nmchain-test-{}", ts));
        Settings {
            listen: "127.0.0.1:0".to_string(),
            data_dir: dir.clone(),
            chain_id: format!("test-chain-{}", ts),
            validator_id: "validator-test".to_string(),
            validator_key_path: dir.join("validator.key.json"),
            app_tokens: HashMap::new(),
            auth_session_url: None,
            auth_cache_ttl_ms: 15_000,
            auth_timeout_ms: 3_000,
        }
    }

    #[test]
    fn payment_and_debit_flow_updates_balances() {
        let mut runtime = ChainRuntime::load(temp_settings()).unwrap();
        runtime
            .submit_payment(
                "refiner",
                PaymentCaptureRequest {
                    request_id: Some("topup-1".to_string()),
                    user_id: "alice".to_string(),
                    tokens: 100,
                    amount_minor: Some(1000),
                    currency: Some("GBP".to_string()),
                    provider: Some("cardstream".to_string()),
                    payment_id: Some("pmt_1".to_string()),
                    checkout_flow: Some("hosted".to_string()),
                    meta: json!({"source": "portal"}),
                },
            )
            .unwrap();
        runtime
            .submit_token(
                "refiner",
                TokenMutationRequest {
                    request_id: Some("grant-1".to_string()),
                    account_scope: AccountScope::User,
                    account_id: "alice".to_string(),
                    entry_type: TokenEntryType::Grant,
                    delta: 20,
                    meta: json!({"source": "promo"}),
                },
            )
            .unwrap();
        runtime
            .submit_token(
                "refiner",
                TokenMutationRequest {
                    request_id: Some("debit-1".to_string()),
                    account_scope: AccountScope::User,
                    account_id: "alice".to_string(),
                    entry_type: TokenEntryType::Debit,
                    delta: -90,
                    meta: json!({"job_id": "job-1"}),
                },
            )
            .unwrap();

        let snapshot = runtime.account_snapshot(&AccountRef::new(AccountScope::User, "alice"));
        assert_eq!(snapshot.balance, 30);
        assert_eq!(snapshot.paid_balance, 30);
        assert_eq!(snapshot.free_balance, 0);
        assert_eq!(snapshot.spent_total, 90);
    }

    #[test]
    fn reserve_release_is_tracked_without_spending_balance() {
        let mut runtime = ChainRuntime::load(temp_settings()).unwrap();
        runtime
            .submit_payment(
                "refiner",
                PaymentCaptureRequest {
                    request_id: Some("topup-1".to_string()),
                    user_id: "alice".to_string(),
                    tokens: 40,
                    amount_minor: None,
                    currency: None,
                    provider: None,
                    payment_id: None,
                    checkout_flow: None,
                    meta: json!({}),
                },
            )
            .unwrap();
        runtime
            .submit_token(
                "refiner",
                TokenMutationRequest {
                    request_id: Some("reserve-1".to_string()),
                    account_scope: AccountScope::User,
                    account_id: "alice".to_string(),
                    entry_type: TokenEntryType::Reserve,
                    delta: 0,
                    meta: json!({"job_id": "job-1", "reserved": 15}),
                },
            )
            .unwrap();
        runtime
            .submit_token(
                "refiner",
                TokenMutationRequest {
                    request_id: Some("release-1".to_string()),
                    account_scope: AccountScope::User,
                    account_id: "alice".to_string(),
                    entry_type: TokenEntryType::Release,
                    delta: 0,
                    meta: json!({"job_id": "job-1", "reserved": 15}),
                },
            )
            .unwrap();

        let snapshot = runtime.account_snapshot(&AccountRef::new(AccountScope::User, "alice"));
        assert_eq!(snapshot.balance, 40);
        assert_eq!(snapshot.reserved, 0);
        assert_eq!(snapshot.available, 40);
    }

    #[test]
    fn request_id_is_idempotent() {
        let mut runtime = ChainRuntime::load(temp_settings()).unwrap();
        runtime
            .submit_payment(
                "refiner",
                PaymentCaptureRequest {
                    request_id: Some("topup-1".to_string()),
                    user_id: "alice".to_string(),
                    tokens: 25,
                    amount_minor: None,
                    currency: None,
                    provider: None,
                    payment_id: None,
                    checkout_flow: None,
                    meta: json!({}),
                },
            )
            .unwrap();
        let duplicate = runtime
            .submit_payment(
                "refiner",
                PaymentCaptureRequest {
                    request_id: Some("topup-1".to_string()),
                    user_id: "alice".to_string(),
                    tokens: 25,
                    amount_minor: None,
                    currency: None,
                    provider: None,
                    payment_id: None,
                    checkout_flow: None,
                    meta: json!({}),
                },
            )
            .unwrap();
        let snapshot = runtime.account_snapshot(&AccountRef::new(AccountScope::User, "alice"));
        assert!(duplicate.duplicate);
        assert_eq!(snapshot.balance, 25);
        assert_eq!(runtime.blocks.len(), 2);
    }
}
