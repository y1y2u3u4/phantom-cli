# Quota-Aware Routing + Concurrency Control + Queuing

## Problem

1. `resolve_account()` uses local USD estimation (`estimate_remaining_quota`) instead of real Anthropic quota API
2. Sticky sessions never break even when an account hits 100% utilization
3. No concurrency limits — unbounded threads, no per-account fairness, no queuing

## Solution: Lightweight Synchronous Approach

All changes in `server/phantom_server.py` only. ~90 lines added/modified. Zero new dependencies.

### 1. Quota-Aware Routing

- New `_get_account_load_score(account)` function
  - Calls `fetch_anthropic_usage()` (60s cache, zero cost on hit)
  - Returns `100 - five_hour.utilization` as score (higher = more available)
  - Falls back to `seven_day.utilization` if `five_hour` is null
  - Falls back to `estimate_remaining_quota()` if no OAuth credentials
- `resolve_account()` uses `_get_account_load_score` instead of `estimate_remaining_quota`
- Sticky sessions break when assigned account's `five_hour.utilization >= 80%`

### 2. Concurrency Control

- `MAX_GLOBAL_CONNECTIONS = 50` — global semaphore
- `MAX_PER_ACCOUNT_CONNECTIONS = 10` — per-account semaphore (lazy-created)
- `CONNECT_QUEUE_TIMEOUT = 30` — seconds before 503

### 3. Queuing

- `threading.Semaphore.acquire(timeout=30)` provides natural queuing
- Timeout → 503 Service Unavailable
- `finally` block ensures semaphore release

### 4. Monitoring

- `/api/health` extended with `connections` stats
- Atomic counters for active global + per-account connections
