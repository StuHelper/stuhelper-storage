import type { components } from './storage.gen';

export type CustodyBinding = components['schemas']['CustodyBinding'];
export type CustodyPage = components['schemas']['CustodyPage'];
export type CustodyPolicy = components['schemas']['CustodyPolicy'];
export type CustodyRequest = components['schemas']['CustodyRequest'];
type Code = 'conflict' | 'forbidden' | 'incompatible' | 'invalid' | 'network' | 'not_found' | 'unauthenticated' | 'unavailable';

export class CustodyError extends Error {
  readonly code: Code;
  readonly uncertain: boolean;
  readonly retryAfterSeconds?: number;
  constructor(code: Code, uncertain = false, retryAfterSeconds?: number) {
    super(code);
    this.code = code;
    this.uncertain = uncertain;
    if (retryAfterSeconds !== undefined) this.retryAfterSeconds = retryAfterSeconds;
  }
}

function record(v: unknown): Record<string, unknown> {
  if (!v || typeof v !== 'object' || Array.isArray(v)) throw new CustodyError('incompatible');
  return v as Record<string, unknown>; // Narrowed object; every consumed field is checked below.
}
function text(v: unknown, max = 512): string { if (typeof v !== 'string' || v.length > max) throw new CustodyError('incompatible'); return v; }
function number(v: unknown): number { if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < 1) throw new CustodyError('incompatible'); return v; }
function choice<T extends string>(v: unknown, options: readonly T[]): T { for (const o of options) if (v === o) return o; throw new CustodyError('incompatible'); }

function parseRetryAfter(res: Response, payload: unknown): number | undefined {
  if (payload && typeof payload === 'object' && !Array.isArray(payload)) {
    const raw = (payload as Record<string, unknown>).retry_after_seconds; // Narrowed object check above.
    if (typeof raw === 'number' && Number.isSafeInteger(raw) && raw >= 1 && raw <= 86400) return raw;
  }
  const header = res.headers.get('Retry-After');
  if (header && /^\d{1,5}$/.test(header)) {
    const parsed = Number(header);
    if (parsed >= 1 && parsed <= 86400) return parsed;
  }
  return undefined;
}

export function parseCustodyBinding(value: unknown): CustodyBinding {
  const v = record(value), until = text(v.authorization_expires_at);
  if (!/(?:Z|[+-]\d\d:\d\d)$/.test(until) || !Number.isFinite(Date.parse(until))) throw new CustodyError('incompatible');
  return {
    id: text(v.id, 128),
    adapter: choice(v.adapter, ['bhpan']),
    revision: number(v.revision),
    state: choice(v.state, ['pending', 'ready', 'blocked', 'credentials_required']),
    authorization_expires_at: until,
    request_id: text(v.request_id, 128),
    last_error: choice(v.last_error, ['', 'authorization_rejected', 'interactive_verification_required', 'dependency_unavailable', 'result_unknown', 'conflict', 'attempts_exhausted', 'credentials_required']),
  };
}
export function parseCustodyPage(value: unknown): CustodyPage {
  const v = record(value); if (!Array.isArray(v.items) || v.items.length > 100) throw new CustodyError('incompatible');
  return { items: v.items.map(parseCustodyBinding), next_cursor: text(v.next_cursor, 128) };
}
export function parseCustodyPolicy(value: unknown): CustodyPolicy {
  const v = record(value), url = text(v.url), digest = text(v.digest), max = number(v.max_term_seconds);
  try { const u = new URL(url); if (u.protocol !== 'https:' || u.username || u.password) throw new Error(); } catch { throw new CustodyError('incompatible'); }
  if (!/^[a-f0-9]{64}$/.test(digest) || max > 366 * 86400 || max < 3600) throw new CustodyError('incompatible');
  return { version: text(v.version, 128), digest, url, max_term_seconds: max };
}

// The host supplies authenticated same-origin fetch. Secrets are never cached,
// logged, returned, or captured in retry objects. Recovery only uses request IDs.
export function custodyAPI(fetcher: typeof fetch = fetch) {
  const base = '/api/v1/storage/custody';
  async function request(path: string, signal: AbortSignal, body?: unknown, key?: string, method?: 'DELETE' | 'GET' | 'POST'): Promise<unknown> {
    const verb = method ?? (body !== undefined ? 'POST' : 'GET');
    const mutation = verb !== 'GET';
    let res: Response;
    try { res = await fetcher(base + path, { signal, method: verb, credentials: 'same-origin', cache: 'no-store', headers: { Accept: 'application/json', ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...(key ? { 'Idempotency-Key': key } : {}) }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) }); }
    catch { throw new CustodyError('network', mutation); }
    if (res.status === 401) throw new CustodyError('unauthenticated');
    if (res.status === 403) throw new CustodyError('forbidden');
    if (res.status === 404) throw new CustodyError('not_found');
    if (res.status === 409) throw new CustodyError('conflict');
    if (res.status === 400 || res.status === 413) throw new CustodyError('invalid');
    const expectedStatus = verb === 'POST' ? 202 : 200;
    if (res.status !== expectedStatus) {
      let errBody: unknown;
      try { errBody = await res.json(); } catch { errBody = undefined; }
      throw new CustodyError('unavailable', mutation, parseRetryAfter(res, errBody));
    }
    try { return await res.json(); } catch { throw new CustodyError('incompatible', mutation); }
  }
  async function binding(path: string, signal: AbortSignal, body: unknown, expected: { id?: string; request?: string }, key?: string, method?: 'DELETE' | 'POST') {
    const value = await request(path, signal, body, key, method);
    try {
      const result = parseCustodyBinding(value);
      if (expected.id && expected.id !== result.id || expected.request && expected.request !== result.request_id) throw new CustodyError('incompatible');
      return result;
    } catch { throw new CustodyError('incompatible', true); }
  }
  return {
    policy: async (signal: AbortSignal) => parseCustodyPolicy(await request('/policy', signal)),
    list: async (signal: AbortSignal, after = '', admin = false) => parseCustodyPage(await request(`${admin ? '/operations' : ''}?limit=20&after=${encodeURIComponent(after)}`, signal)),
    requestStatus: async (key: string, signal: AbortSignal) => parseCustodyBinding(await request(`/requests/${encodeURIComponent(key)}`, signal)),
    submit: (key: string, body: CustodyRequest, signal: AbortSignal, id?: string) => binding(id ? `/${encodeURIComponent(id)}/reauthorize` : '', signal, body, { id: id ?? key, request: key }, key, 'POST'),
    resume: (item: CustodyBinding, signal: AbortSignal, admin = false) => binding(`${admin ? '/operations' : ''}/${encodeURIComponent(item.id)}/resume`, signal, { request_id: item.request_id, revision: item.revision }, { id: item.id, request: item.request_id }, undefined, 'POST'),
    remove: (id: string, key: string, signal: AbortSignal) => binding(`/${encodeURIComponent(id)}`, signal, undefined, { id }, key, 'DELETE'),
  };
}
