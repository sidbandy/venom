import type { Policy } from './policy';

export interface Logger {
  debug(msg: string, ...args: unknown[]): void;
  info(msg: string, ...args: unknown[]): void;
  warn(msg: string, ...args: unknown[]): void;
  error(msg: string, ...args: unknown[]): void;
}

export interface HttpRequestOptions {
  headers?: Record<string, string>;
  /** Per-request timeout in milliseconds. */
  timeoutMs?: number;
  /** Skip the cache for this request (still records the response). */
  noCache?: boolean;
}

/**
 * The engine's single outbound HTTP surface. Every network call in Venom goes
 * through one implementation of this interface, which enforces the allowlist of
 * permitted hosts, honors offline mode, and applies backoff. Centralizing egress
 * is what makes the zero-telemetry promise auditable in one place (SPEC.md §8, §9.2).
 */
export interface HttpClient {
  getJson<T>(url: string, opts?: HttpRequestOptions): Promise<T>;
  getText(url: string, opts?: HttpRequestOptions): Promise<string>;
  getBuffer(url: string, opts?: HttpRequestOptions): Promise<Buffer>;
  postJson<T>(url: string, body: unknown, opts?: HttpRequestOptions): Promise<T>;
}

/**
 * A namespaced key/value cache with TTLs, backed by local SQLite. Used for
 * registry/OSV lookups and other idempotent network results so runs are fast and
 * repeatable, and so offline mode can serve prior results.
 */
export interface Cache {
  get<T>(namespace: string, key: string): T | undefined;
  set<T>(namespace: string, key: string, value: T, ttlMs?: number): void;
  delete(namespace: string, key: string): void;
}

/** Fully-resolved runtime configuration for a scan. */
export interface VenomConfig {
  /** When true, no network calls are made; only cache/bundled data is used. */
  offline: boolean;
  /** Absolute path to Venom's local data directory (cache DB, score history). */
  dataDir: string;
  /** Loaded `.venom.yml` policy, if present. */
  policy?: Policy;
}

/**
 * The context threaded into every module. Carries the project location, resolved
 * config, the shared network client and cache, and a logger. Modules receive
 * everything they need to reach the outside world through this object and nothing
 * else — keeping side effects explicit and testable.
 */
export interface ScanContext {
  /** Absolute path to the project under analysis. */
  projectRoot: string;
  config: VenomConfig;
  http: HttpClient;
  cache: Cache;
  logger: Logger;
}
