// ── Auth ─────────────────────────────────────────────────────────────────────

export interface AuthCheckResponse {
  authenticated: boolean;
  needs_setup: boolean;
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

export interface Quota {
  monthly_limit_usd?: number;
  reset_day?: number;
}

export interface Account {
  id: string;
  name: string;
  status: 'active' | 'exhausted' | 'disabled';
  upstream_proxy: UpstreamProxy;
  has_credentials: boolean;
  quota: Quota;
  estimated_remaining_usd: number;
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
  quota?: Quota;
}

export interface UpdateAccountPayload {
  name?: string;
  upstream_proxy?: UpstreamProxyInput;
  quota?: Quota;
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

// ── Common ───────────────────────────────────────────────────────────────────

export interface MessageResponse {
  message: string;
}

export interface TestResponse {
  success: boolean;
  message: string;
}
