use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountScope {
    User,
    Team,
    System,
}

impl Display for AccountScope {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::User => write!(f, "user"),
            Self::Team => write!(f, "team"),
            Self::System => write!(f, "system"),
        }
    }
}

impl FromStr for AccountScope {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "user" | "users" | "personal" => Ok(Self::User),
            "team" | "teams" => Ok(Self::Team),
            "system" | "service" => Ok(Self::System),
            other => Err(format!("unsupported account scope '{other}'")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub struct AccountRef {
    pub scope: AccountScope,
    pub id: String,
}

impl AccountRef {
    pub fn new(scope: AccountScope, id: impl Into<String>) -> Self {
        Self {
            scope,
            id: id.into(),
        }
    }

    pub fn key(&self) -> String {
        format!("{}:{}", self.scope, self.id)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenEntryType {
    Topup,
    Grant,
    Refund,
    Cashout,
    Debit,
    Reserve,
    Release,
    Sync,
    Adjust,
}

impl Display for TokenEntryType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Topup => write!(f, "topup"),
            Self::Grant => write!(f, "grant"),
            Self::Refund => write!(f, "refund"),
            Self::Cashout => write!(f, "cashout"),
            Self::Debit => write!(f, "debit"),
            Self::Reserve => write!(f, "reserve"),
            Self::Release => write!(f, "release"),
            Self::Sync => write!(f, "sync"),
            Self::Adjust => write!(f, "adjust"),
        }
    }
}

impl FromStr for TokenEntryType {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "topup" => Ok(Self::Topup),
            "grant" => Ok(Self::Grant),
            "refund" => Ok(Self::Refund),
            "cashout" => Ok(Self::Cashout),
            "debit" => Ok(Self::Debit),
            "reserve" => Ok(Self::Reserve),
            "release" => Ok(Self::Release),
            "sync" => Ok(Self::Sync),
            "adjust" => Ok(Self::Adjust),
            other => Err(format!("unsupported token entry type '{other}'")),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct IdentityState {
    pub role: Option<String>,
    pub groups: Vec<String>,
    pub active_team: Option<Value>,
    pub team_count: u64,
    pub pending_invitation_count: u64,
    pub email: Option<String>,
    pub provider: Option<String>,
    pub subject: Option<String>,
    pub last_login_at: Option<String>,
    pub last_login_system: Option<String>,
    pub login_count: u64,
    pub updated_at: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountState {
    pub scope: AccountScope,
    pub account_id: String,
    pub balance: i64,
    pub paid_balance: i64,
    pub free_balance: i64,
    pub reserved: i64,
    pub last_topup_tokens: i64,
    pub last_topup_at: Option<String>,
    pub updated_at: Option<String>,
    pub spent_total: i64,
    pub cashout_total: i64,
    pub shortfall_total: i64,
    pub free_grant_total: i64,
    pub reservations: std::collections::BTreeMap<String, i64>,
    pub identity: IdentityState,
}

impl AccountState {
    pub fn new(account: &AccountRef) -> Self {
        Self {
            scope: account.scope,
            account_id: account.id.clone(),
            balance: 0,
            paid_balance: 0,
            free_balance: 0,
            reserved: 0,
            last_topup_tokens: 0,
            last_topup_at: None,
            updated_at: None,
            spent_total: 0,
            cashout_total: 0,
            shortfall_total: 0,
            free_grant_total: 0,
            reservations: std::collections::BTreeMap::new(),
            identity: IdentityState::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountSnapshot {
    pub scope: AccountScope,
    pub account_id: String,
    pub balance: i64,
    pub tokens: i64,
    pub paid_balance: i64,
    pub free_balance: i64,
    pub reserved: i64,
    pub available: i64,
    pub in_use: i64,
    pub last_topup_tokens: i64,
    pub capacity: i64,
    pub display_capacity: i64,
    pub low_threshold: i64,
    pub status: String,
    pub last_topup_at: Option<String>,
    pub updated_at: Option<String>,
    pub spent_total: i64,
    pub cashout_total: i64,
    pub shortfall_total: i64,
    pub free_grant_total: i64,
    pub identity: Option<IdentityState>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LedgerEntry {
    pub tx_id: String,
    pub request_id: Option<String>,
    pub block_index: u64,
    pub block_hash: String,
    pub ts: String,
    pub account_scope: AccountScope,
    pub account_id: String,
    #[serde(rename = "type")]
    pub entry_type: String,
    pub delta: i64,
    pub balance_after: i64,
    pub paid_after: i64,
    pub free_after: i64,
    pub reserved_after: i64,
    pub shortfall: i64,
    pub actor_app: String,
    pub meta: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxEnvelope {
    pub tx_id: String,
    pub request_id: Option<String>,
    pub ts: String,
    pub actor_app: String,
    pub event: ChainEvent,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum ChainEvent {
    Genesis(GenesisEvent),
    IdentityUpsert(IdentityUpsertRequest),
    LoginObserved(LoginObservedRequest),
    PaymentCaptured(PaymentCaptureRequest),
    TokenMutation(TokenMutationRequest),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenesisEvent {
    pub chain_id: String,
    pub validator_id: String,
    pub validator_public_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityUpsertRequest {
    pub request_id: Option<String>,
    pub user_id: String,
    pub role: Option<String>,
    pub email: Option<String>,
    pub provider: Option<String>,
    pub subject: Option<String>,
    #[serde(default)]
    pub meta: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LoginObservedRequest {
    pub request_id: Option<String>,
    pub user_id: String,
    pub system: String,
    pub auth_mode: Option<String>,
    pub session_id: Option<String>,
    pub remote_addr: Option<String>,
    #[serde(default)]
    pub meta: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaymentCaptureRequest {
    pub request_id: Option<String>,
    pub user_id: String,
    pub tokens: i64,
    pub amount_minor: Option<i64>,
    pub currency: Option<String>,
    pub provider: Option<String>,
    pub payment_id: Option<String>,
    pub checkout_flow: Option<String>,
    #[serde(default)]
    pub meta: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenMutationRequest {
    pub request_id: Option<String>,
    pub account_scope: AccountScope,
    pub account_id: String,
    pub entry_type: TokenEntryType,
    pub delta: i64,
    #[serde(default)]
    pub meta: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub index: u64,
    pub chain_id: String,
    pub ts: String,
    pub previous_hash: String,
    pub transactions_hash: String,
    pub state_hash: String,
    pub validator_id: String,
    pub validator_public_key: String,
    pub signature_hex: String,
    pub hash: String,
    pub transactions: Vec<TxEnvelope>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainStatus {
    pub chain_id: String,
    pub height: u64,
    pub head_hash: String,
    pub validator_id: String,
    pub validator_public_key: String,
    pub account_count: usize,
    pub auth_mode: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitResult {
    pub duplicate: bool,
    pub tx_id: Option<String>,
    pub block_index: u64,
    pub chain_height: u64,
    pub head_hash: String,
    pub snapshot: Option<AccountSnapshot>,
    pub entry: Option<LedgerEntry>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ListQuery {
    pub limit: Option<usize>,
}

pub fn now_rfc3339() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}
