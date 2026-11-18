import test from 'node:test';
import assert from 'node:assert/strict';
import {
  CustodyError,
  custodyAPI,
  parseCustodyBinding,
  parseCustodyPage,
  parseCustodyPolicy,
} from './custody-browser.ts';

const validBinding = {
  id: '11111111-1111-4111-8111-111111111111',
  adapter: 'bhpan' as const,
  revision: 1,
  state: 'ready' as const,
  authorization_expires_at: '2026-12-01T00:00:00Z',
  request_id: '22222222-2222-4222-8222-222222222222',
  last_error: '' as const,
};

const validPolicy = {
  version: 'custody-v1',
  digest: 'a'.repeat(64),
  url: 'https://stuhelper.example/custody-policy',
  max_term_seconds: 86400 * 30,
};

function expectCustodyError(fn: () => unknown, code: string, uncertain = false) {
  assert.throws(fn, (err: unknown) => {
    assert.ok(err instanceof CustodyError);
    assert.equal(err.code, code);
    assert.equal(err.uncertain, uncertain);
    return true;
  });
}

async function expectAsyncCustodyError(fn: () => Promise<unknown>, code: string, uncertain = false) {
  await assert.rejects(fn, (err: unknown) => {
    assert.ok(err instanceof CustodyError);
    assert.equal(err.code, code);
    assert.equal(err.uncertain, uncertain);
    return true;
  });
}

test('parseCustodyBinding validates schema and rejects malformed payloads', () => {
  assert.deepEqual(parseCustodyBinding(validBinding), validBinding);
  expectCustodyError(() => parseCustodyBinding(null), 'incompatible');
  expectCustodyError(() => parseCustodyBinding([]), 'incompatible');
  expectCustodyError(() => parseCustodyBinding({ ...validBinding, adapter: 'unknown' }), 'incompatible');
  expectCustodyError(() => parseCustodyBinding({ ...validBinding, revision: 0 }), 'incompatible');
  expectCustodyError(() => parseCustodyBinding({ ...validBinding, authorization_expires_at: '2026-12-01 00:00:00' }), 'incompatible');
  expectCustodyError(() => parseCustodyBinding({ ...validBinding, last_error: 'unexpected_code' }), 'incompatible');
});

test('parseCustodyPage and parseCustodyPolicy enforce bounds and HTTPS policy URLs', () => {
  const page = parseCustodyPage({ items: [validBinding], next_cursor: '' });
  assert.equal(page.items.length, 1);
  expectCustodyError(() => parseCustodyPage({ items: new Array(101).fill(validBinding), next_cursor: '' }), 'incompatible');

  assert.deepEqual(parseCustodyPolicy(validPolicy), validPolicy);
  expectCustodyError(() => parseCustodyPolicy({ ...validPolicy, url: 'http://insecure.example/policy' }), 'incompatible');
  expectCustodyError(() => parseCustodyPolicy({ ...validPolicy, url: 'https://user:secret@stuhelper.example/policy' }), 'incompatible');
  expectCustodyError(() => parseCustodyPolicy({ ...validPolicy, digest: 'xyz' }), 'incompatible');
  expectCustodyError(() => parseCustodyPolicy({ ...validPolicy, max_term_seconds: 60 }), 'incompatible');
});

test('custodyAPI maps HTTP status codes, network failures and identity mismatches without retaining secrets', async () => {
  const controller = new AbortController();
  const sampleSecret = 'TopSecretCustodyPassword!42';
  const submitPayload = {
    adapter: 'bhpan' as const,
    credential: { username: 'student', password: sampleSecret },
    until: '2026-12-01T00:00:00Z',
    consent: { accepted: true as const, version: 'custody-v1', digest: 'a'.repeat(64) },
  };

  for (const [status, code] of [
    [401, 'unauthenticated'],
    [403, 'forbidden'],
    [409, 'conflict'],
    [400, 'invalid'],
    [413, 'invalid'],
  ] as const) {
    const api = custodyAPI(async () => new Response(JSON.stringify({ code: 'err' }), { status }));
    await expectAsyncCustodyError(() => api.policy(controller.signal), code, false);
    await expectAsyncCustodyError(() => api.submit(validBinding.request_id, submitPayload, controller.signal), code, false);
  }

  // 503 on GET has uncertain=false; 503 or network drop on POST mutation marks uncertain=true and never embeds secrets.
  const unavailableAPI = custodyAPI(async () => new Response('{"code":"storage_unavailable"}', { status: 503 }));
  await expectAsyncCustodyError(() => unavailableAPI.requestStatus(validBinding.request_id, controller.signal), 'unavailable', false);
  await assert.rejects(
    () => unavailableAPI.submit(validBinding.request_id, submitPayload, controller.signal),
    (err: unknown) => {
      assert.ok(err instanceof CustodyError);
      assert.equal(err.code, 'unavailable');
      assert.equal(err.uncertain, true);
      assert.equal(JSON.stringify(err).includes(sampleSecret), false);
      assert.equal(String(err.message).includes(sampleSecret), false);
      return true;
    },
  );

  const offlineAPI = custodyAPI(async () => {
    throw new TypeError('network down');
  });
  await expectAsyncCustodyError(() => offlineAPI.list(controller.signal), 'network', false);
  await expectAsyncCustodyError(() => offlineAPI.submit(validBinding.request_id, submitPayload, controller.signal), 'network', true);

  // Successful 202 submit and 202 resume verify request headers, paths and returned IDs/request_ids.
  const calls: Array<{ url: string; method?: string; idempotency?: string }> = [];
  const okAPI = custodyAPI(async (input, init) => {
    const headers = init?.headers as Record<string, string> | undefined;
    calls.push({ url: String(input), method: init?.method, idempotency: headers?.['Idempotency-Key'] });
    if (String(input).endsWith('/policy')) {
      return new Response(JSON.stringify(validPolicy), { status: 200 });
    }
    return new Response(
      JSON.stringify({
        ...validBinding,
        id: validBinding.request_id,
      }),
      { status: 202 },
    );
  });
  const policy = await okAPI.policy(controller.signal);
  assert.equal(policy.version, 'custody-v1');
  const submitted = await okAPI.submit(validBinding.request_id, submitPayload, controller.signal);
  assert.equal(submitted.id, validBinding.request_id);
  const resumed = await okAPI.resume(submitted, controller.signal, true);
  assert.equal(resumed.request_id, validBinding.request_id);
  assert.equal(calls[1]?.method, 'POST');
  assert.equal(calls[1]?.idempotency, validBinding.request_id);
  assert.ok(calls[2]?.url.includes('/operations/'));

  // Mismatched returned request_id on mutation fails closed with uncertain=true.
  const mismatchAPI = custodyAPI(async () => new Response(JSON.stringify({ ...validBinding, id: validBinding.request_id, request_id: 'tampered' }), { status: 202 }));
  await expectAsyncCustodyError(() => mismatchAPI.submit(validBinding.request_id, submitPayload, controller.signal), 'incompatible', true);
});
