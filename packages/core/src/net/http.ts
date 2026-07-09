import type { HttpClient, HttpRequestOptions, Logger } from '../types/context';
import { DisallowedHostError, HttpError, OfflineError } from './errors';
import { DEFAULT_ALLOWED_HOSTS, isAllowedHost } from './hosts';

/** Injectable fetch, so tests never touch the real network. */
export type FetchFn = typeof fetch;

export interface VenomHttpClientOptions {
  offline?: boolean;
  logger?: Logger;
  /** Override the host allowlist (mainly for tests). Defaults to {@link DEFAULT_ALLOWED_HOSTS}. */
  allowedHosts?: ReadonlySet<string>;
  /** Injectable fetch implementation. Defaults to the global `fetch`. */
  fetchImpl?: FetchFn;
  userAgent?: string;
  /** Max retry attempts for transient failures (429/5xx/network). Default 3. */
  maxRetries?: number;
  /** Base backoff in ms; grows exponentially with jitter. Default 300. */
  baseBackoffMs?: number;
  /** Default per-request timeout in ms. Default 15000. */
  defaultTimeoutMs?: number;
}

const RETRYABLE_STATUS = new Set([408, 425, 429, 500, 502, 503, 504]);

/**
 * The single outbound HTTP client for the entire engine. Every network call in
 * Venom goes through here, which:
 *   - refuses any host not on the allowlist ({@link DisallowedHostError}),
 *   - refuses all requests in offline mode ({@link OfflineError}),
 *   - upgrades/requires HTTPS,
 *   - applies per-request timeouts and exponential backoff on transient errors.
 *
 * Concentrating egress in one small, auditable class is what turns the
 * zero-telemetry design goal into something a reviewer can actually verify.
 */
export class VenomHttpClient implements HttpClient {
  readonly #offline: boolean;
  readonly #logger: Logger | undefined;
  readonly #allowedHosts: ReadonlySet<string>;
  readonly #fetch: FetchFn;
  readonly #userAgent: string;
  readonly #maxRetries: number;
  readonly #baseBackoffMs: number;
  readonly #defaultTimeoutMs: number;

  constructor(opts: VenomHttpClientOptions = {}) {
    this.#offline = opts.offline ?? false;
    this.#logger = opts.logger;
    this.#allowedHosts = opts.allowedHosts ?? DEFAULT_ALLOWED_HOSTS;
    const fetchImpl = opts.fetchImpl ?? globalThis.fetch;
    if (!fetchImpl) {
      throw new Error(
        'No fetch implementation available (need Node >=18 or an injected fetchImpl).',
      );
    }
    this.#fetch = fetchImpl;
    this.#userAgent = opts.userAgent ?? 'venom-scanner';
    this.#maxRetries = opts.maxRetries ?? 3;
    this.#baseBackoffMs = opts.baseBackoffMs ?? 300;
    this.#defaultTimeoutMs = opts.defaultTimeoutMs ?? 15_000;
  }

  async getJson<T>(url: string, opts?: HttpRequestOptions): Promise<T> {
    const res = await this.#request('GET', url, opts);
    return (await res.json()) as T;
  }

  async getText(url: string, opts?: HttpRequestOptions): Promise<string> {
    const res = await this.#request('GET', url, opts);
    return res.text();
  }

  async getBuffer(url: string, opts?: HttpRequestOptions): Promise<Buffer> {
    const res = await this.#request('GET', url, opts);
    return Buffer.from(await res.arrayBuffer());
  }

  async postJson<T>(url: string, body: unknown, opts?: HttpRequestOptions): Promise<T> {
    const res = await this.#request('POST', url, opts, JSON.stringify(body));
    return (await res.json()) as T;
  }

  /** Validate the target host against the allowlist and HTTPS requirement. */
  #guard(url: string): URL {
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      throw new Error(`Invalid URL: ${url}`);
    }
    if (parsed.protocol !== 'https:') {
      throw new DisallowedHostError(parsed.host, url);
    }
    if (!isAllowedHost(parsed.hostname, this.#allowedHosts)) {
      throw new DisallowedHostError(parsed.hostname, url);
    }
    return parsed;
  }

  async #request(
    method: 'GET' | 'POST',
    url: string,
    opts: HttpRequestOptions | undefined,
    body?: string,
  ): Promise<Response> {
    this.#guard(url);
    if (this.#offline) {
      throw new OfflineError(url);
    }

    const timeoutMs = opts?.timeoutMs ?? this.#defaultTimeoutMs;
    const headers: Record<string, string> = {
      'user-agent': this.#userAgent,
      ...(body ? { 'content-type': 'application/json' } : {}),
      ...opts?.headers,
    };

    let lastError: unknown;
    for (let attempt = 0; attempt <= this.#maxRetries; attempt++) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const init: RequestInit = { method, headers, signal: controller.signal };
        if (body !== undefined) init.body = body;
        const res = await this.#fetch(url, init);
        if (res.ok) {
          return res;
        }
        if (RETRYABLE_STATUS.has(res.status) && attempt < this.#maxRetries) {
          const delay = this.#backoffDelay(attempt, res.headers.get('retry-after'));
          this.#logger?.debug(`HTTP ${res.status} for ${url}; retrying in ${delay}ms`);
          await sleep(delay);
          continue;
        }
        throw new HttpError(res.status, url, res.statusText);
      } catch (err) {
        lastError = err;
        // Do not retry a definitive HTTP error (already handled above) or an abort
        // that isn't a transient network blip on the last attempt.
        if (err instanceof HttpError) throw err;
        if (attempt < this.#maxRetries) {
          const delay = this.#backoffDelay(attempt, null);
          this.#logger?.debug(`Network error for ${url} (${String(err)}); retrying in ${delay}ms`);
          await sleep(delay);
          continue;
        }
      } finally {
        clearTimeout(timer);
      }
    }
    throw lastError instanceof Error
      ? lastError
      : new Error(`Request to ${url} failed after ${this.#maxRetries + 1} attempts`);
  }

  #backoffDelay(attempt: number, retryAfter: string | null): number {
    if (retryAfter) {
      const seconds = Number(retryAfter);
      if (Number.isFinite(seconds) && seconds >= 0) {
        return Math.min(seconds * 1000, 60_000);
      }
    }
    const exp = this.#baseBackoffMs * 2 ** attempt;
    const jitter = Math.random() * this.#baseBackoffMs;
    return Math.min(exp + jitter, 30_000);
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
