// ── Auth ─────────────────────────────────────────────────────────────────────

export interface AuthCheckResponse {
  authenticated: boolean;
  needs_setup: boolean;
  role?: 'admin' | 'member';
  username?: string | null;
}

// ── Keys ─────────────────────────────────────────────────────────────────────

export interface ApiKey {
  id: string;
  name: string;
  masked_key: string;
  account_id: string | null;
  account_name: string | null;
  created_at: string;
  last_used_at: string | null;
  last_used_ip: string | null;
  usage_this_month: {
    connections: number;
    estimated_cost_usd: number;
  } | null;
}

export interface KeysListResponse {
  keys: ApiKey[];
}

export interface KeyCreateResponse {
  id: string;
  name: string;
  key: string;
  created_at: string;
}

// ── Accounts ─────────────────────────────────────────────────────────────────

export interface UpstreamProxy {
  type: 'direct' | 'http' | 'socks5';
  host: string;
  port: number;
  has_auth: boolean;
}

export interface UpstreamProxyInput {
  type: 'direct' | 'http' | 'socks5';
  host?: string;
  port?: number;
  username?: string;
  password?: string;
}

export interface RealQuota {
  subscription_type: string | null;
  five_hour_pct: number | null;
  seven_day_pct: number | null;
  error: string | null;
}

export interface QuotaLimit {
  utilization: number;
  resets_at: string | null;
  resets_in: string | null;
}

export interface AccountQuotaResponse {
  subscription_type: string | null;
  five_hour: QuotaLimit | null;
  seven_day: QuotaLimit | null;
  seven_day_opus: QuotaLimit | null;
  seven_day_sonnet: QuotaLimit | null;
  extra_usage: { is_enabled: boolean; utilization: number | null } | null;
  has_credentials: boolean;
  error: string | null;
  queried_at: number | null;
}

export interface AccountQuota {
  monthly_limit_usd?: number;
  reset_day?: number;
  daily_limit_connections?: number | null;
  session_max_pct?: number;
  daily_budget_pct?: number;
}

export interface Account {
  id: string;
  name: string;
  status: 'active' | 'exhausted' | 'disabled';
  upstream_proxy: UpstreamProxy;
  has_credentials: boolean;
  real_quota: RealQuota | null;
  quota?: AccountQuota;
  daily_connections_today?: number;
  daily_baseline_weekly_pct?: number | null;
  current_weekly_pct?: number | null;
  current_session_pct?: number | null;
  created_at: string;
  updated_at: string;
}

export interface AccountsListResponse {
  accounts: Account[];
}

export interface AccountCreateResponse {
  id: string;
  name: string;
  credentials_dir: string;
}

export interface CreateAccountPayload {
  name: string;
  upstream_proxy?: UpstreamProxyInput;
  quota?: AccountQuota;
}

export interface UpdateAccountPayload {
  name?: string;
  upstream_proxy?: UpstreamProxyInput;
  quota?: AccountQuota;
  status?: 'active' | 'exhausted' | 'disabled';
}

// ── Usage ────────────────────────────────────────────────────────────────────

export interface SessionRecord {
  started_at: string;
  ended_at: string;
  target: string;
  bytes_up: number;
  bytes_down: number;
}

export interface UsageKeyData {
  account_id?: string;
  connections: number;
  bytes_upstream: number;
  bytes_downstream: number;
  estimated_tokens_in: number;
  estimated_tokens_out: number;
  estimated_cost_usd: number;
  sessions?: SessionRecord[];
}

export interface UsageAccountData {
  account_name: string;
  connections: number;
  bytes_upstream: number;
  bytes_downstream: number;
  estimated_cost_usd: number;
  daily_connections_today?: number;
  daily_limit_connections?: number | null;
}

export interface UsageResponse {
  month: string;
  by_key: Record<string, UsageKeyData>;
  by_account: Record<string, UsageAccountData>;
  available_months: string[];
}

// ── Assignments ──────────────────────────────────────────────────────────────

export interface AssignmentEntry {
  account_id: string;
  assigned_at: string;
  reason: string;
}

export interface AssignmentsResponse {
  by_api_key: Record<string, AssignmentEntry>;
  by_client_ip: Record<string, AssignmentEntry>;
}

// ── Members ─────────────────────────────────────────────────────────────────

export interface Member {
  id: string;
  username: string;
  role: 'admin' | 'member';
  status: 'active' | 'disabled';
  created_at: string | null;
  last_login_at: string | null;
  last_login_ip: string | null;
  key_count: number;
}

export interface MembersListResponse {
  members: Member[];
}

// ── Invites ─────────────────────────────────────────────────────────────────

export interface Invite {
  token: string;
  created_at: string | null;
  expires_at: string;
  max_uses: number;
  use_count: number;
  status: 'active' | 'expired' | 'exhausted';
}

export interface InvitesListResponse {
  invites: Invite[];
}

export interface InviteCreateResponse {
  token: string;
  invite_url: string;
  expires_at: string;
  max_uses: number;
}

export interface InviteCheckResponse {
  valid: boolean;
  error?: string;
}

export interface InviteRegisterResponse {
  message: string;
  username: string;
}

// ── Health ───────────────────────────────────────────────────────────────────

export interface HealthPerAccount {
  total: number;
  idle: number;
  active: number;
  name: string;
}

export interface HealthConnections {
  active: number;
  idle: number;
  truly_active: number;
  max: number;
  per_account: Record<string, HealthPerAccount>;
  per_account_max: number;
  idle_timeout: string;
}

export interface HealthResponse {
  status: string;
  connections: HealthConnections;
}

// ── Common ───────────────────────────────────────────────────────────────────

export interface MessageResponse {
  message: string;
}

export interface TestResponse {
  success: boolean;
  message: string;
}
