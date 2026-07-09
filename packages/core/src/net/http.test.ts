import { describe, expect, it, vi } from 'vitest';
import { VenomHttpClient, type FetchFn } from './http';
import { DisallowedHostError, HttpError, OfflineError } from './errors';

/** Build a fetch stub that returns a JSON 200 by default. */
function jsonFetch(payload: unknown, status = 200): FetchFn {
  return vi.fn(
    async () =>
      new Response(JSON.stringify(payload), {
        status,
        headers: { 'content-type': 'application/json' },
      }),
  ) as unknown as FetchFn;
}

describe('VenomHttpClient — egress control', () => {
  it('refuses hosts that are not on the allowlist', async () => {
    const fetchImpl = jsonFetch({ ok: true });
    const client = new VenomHttpClient({ fetchImpl });
    await expect(client.getJson('https://evil.example.com/exfil')).rejects.toBeInstanceOf(
      DisallowedHostError,
    );
    // The forbidden request must never reach fetch.
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('refuses non-HTTPS URLs even for allowlisted hosts', async () => {
    const fetchImpl = jsonFetch({ ok: true });
    const client = new VenomHttpClient({ fetchImpl });
    await expect(client.getJson('http://api.osv.dev/v1/query')).rejects.toBeInstanceOf(
      DisallowedHostError,
    );
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('allows an allowlisted HTTPS host and parses JSON', async () => {
    const fetchImpl = jsonFetch({ vulns: [] });
    const client = new VenomHttpClient({ fetchImpl });
    const body = await client.getJson<{ vulns: unknown[] }>('https://api.osv.dev/v1/query');
    expect(body).toEqual({ vulns: [] });
    expect(fetchImpl).toHaveBeenCalledOnce();
  });

  it('makes zero network calls in offline mode', async () => {
    const fetchImpl = jsonFetch({ ok: true });
    const client = new VenomHttpClient({ fetchImpl, offline: true });
    await expect(client.getJson('https://api.osv.dev/v1/query')).rejects.toBeInstanceOf(
      OfflineError,
    );
    expect(fetchImpl).not.toHaveBeenCalled();
  });
});

describe('VenomHttpClient — resilience', () => {
  it('retries transient 5xx then succeeds', async () => {
    let calls = 0;
    const fetchImpl = vi.fn(async () => {
      calls += 1;
      if (calls < 3) return new Response('busy', { status: 503 });
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }) as unknown as FetchFn;
    const client = new VenomHttpClient({ fetchImpl, baseBackoffMs: 1, maxRetries: 5 });
    const body = await client.getJson<{ ok: boolean }>('https://registry.npmjs.org/lodash');
    expect(body).toEqual({ ok: true });
    expect(calls).toBe(3);
  });

  it('throws HttpError after exhausting retries', async () => {
    const fetchImpl = vi.fn(
      async () => new Response('nope', { status: 500 }),
    ) as unknown as FetchFn;
    const client = new VenomHttpClient({ fetchImpl, baseBackoffMs: 1, maxRetries: 2 });
    await expect(client.getJson('https://registry.npmjs.org/lodash')).rejects.toBeInstanceOf(
      HttpError,
    );
    // initial + 2 retries
    expect(fetchImpl).toHaveBeenCalledTimes(3);
  });

  it('does not retry a non-retryable 404', async () => {
    const fetchImpl = vi.fn(
      async () => new Response('missing', { status: 404 }),
    ) as unknown as FetchFn;
    const client = new VenomHttpClient({ fetchImpl, baseBackoffMs: 1, maxRetries: 3 });
    await expect(client.getJson('https://registry.npmjs.org/nope')).rejects.toBeInstanceOf(
      HttpError,
    );
    expect(fetchImpl).toHaveBeenCalledOnce();
  });
});
