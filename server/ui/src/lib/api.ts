import type {
  AuthCheckResponse,
  MessageResponse,
  KeysListResponse,
  KeyCreateResponse,
  AccountsListResponse,
  AccountCreateResponse,
  CreateAccountPayload,
  UpdateAccountPayload,
  TestResponse,
  UsageResponse,
  AssignmentsResponse,
} from './types';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || '';

export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const options: RequestInit = {
    method,
    headers: {},
    credentials: 'same-origin',
  };
  if (body !== undefined) {
    (options.headers as Record<string, string>)['Content-Type'] = 'application/json';
    options.body = JSON.stringify(body);
  }

  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, options);
  } catch (e) {
    throw new ApiError(`Network error: ${(e as Error).message}`, 0);
  }

  const text = await response.text();
  let data: any = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = { message: text };
    }
  }

  if (!response.ok) {
    const msg = data?.error || data?.message || `Server error ${response.status}`;
    throw new ApiError(msg, response.status);
  }

  return data as T;
}

export const api = {
  // Auth
  checkAuth: () => request<AuthCheckResponse>('GET', '/api/auth/check'),
  setup: (password: string) => request<MessageResponse>('POST', '/api/auth/setup', { password }),
  login: (password: string) => request<MessageResponse>('POST', '/api/auth/login', { password }),
  logout: () => request<MessageResponse>('POST', '/api/auth/logout'),

  // Keys
  listKeys: () => request<KeysListResponse>('GET', '/api/keys'),
  createKey: (name: string, accountId?: string) =>
    request<KeyCreateResponse>('POST', '/api/keys', { name, account_id: accountId }),
  deleteKey: (id: string) => request<MessageResponse>('DELETE', `/api/keys/${encodeURIComponent(id)}`),
  assignKeyAccount: (keyId: string, accountId: string) =>
    request<MessageResponse>('PUT', `/api/keys/${encodeURIComponent(keyId)}/account`, {
      account_id: accountId,
    }),
  unassignKeyAccount: (keyId: string) =>
    request<MessageResponse>('DELETE', `/api/keys/${encodeURIComponent(keyId)}/account`),

  // Accounts
  listAccounts: () => request<AccountsListResponse>('GET', '/api/accounts'),
  createAccount: (data: CreateAccountPayload) =>
    request<AccountCreateResponse>('POST', '/api/accounts', data),
  updateAccount: (id: string, data: UpdateAccountPayload) =>
    request<MessageResponse>('PUT', `/api/accounts/${encodeURIComponent(id)}`, data),
  deleteAccount: (id: string) =>
    request<MessageResponse>('DELETE', `/api/accounts/${encodeURIComponent(id)}`),
  testAccount: (id: string) =>
    request<TestResponse>('POST', `/api/accounts/${encodeURIComponent(id)}/test`),
  uploadCredentials: (id: string, files: Record<string, string>) =>
    request<MessageResponse>('POST', `/api/accounts/${encodeURIComponent(id)}/credentials`, {
      files,
    }),

  // Usage
  getUsage: (month?: string) =>
    request<UsageResponse>('GET', `/api/usage${month ? `?month=${month}` : ''}`),

  // Assignments
  getAssignments: () => request<AssignmentsResponse>('GET', '/api/assignments'),
};
