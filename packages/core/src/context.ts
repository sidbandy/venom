import { join } from 'node:path';
import { SqliteCache } from './cache/sqlite-cache';
import { VenomHttpClient } from './net/http';
import { ConsoleLogger } from './logger';
import type { Cache, HttpClient, Logger, ScanContext, VenomConfig } from './types/context';
import type { Policy } from './types/policy';

export interface CreateScanContextOptions {
  projectRoot: string;
  /** When true, no network calls are made; only cache/bundled data is used. */
  offline?: boolean;
  /** Where the cache DB and score history live. Defaults to `<projectRoot>/.venom-cache`. */
  dataDir?: string;
  policy?: Policy;
  logger?: Logger;
  /** Override the HTTP client (tests). */
  http?: HttpClient;
  /** Override the cache (tests). */
  cache?: Cache;
}

/** A {@link ScanContext} plus a `dispose()` that releases resources it owns. */
export interface ScanContextHandle extends ScanContext {
  dispose(): void;
}

/**
 * Assemble a ready-to-use {@link ScanContext}: the audited HTTP client, the local
 * SQLite cache, a logger, and resolved config. This is the one place callers
 * (CLI, CI action, plugin) wire the engine's side-effecting dependencies, so
 * every surface behaves identically.
 */
export function createScanContext(options: CreateScanContextOptions): ScanContextHandle {
  const offline = options.offline ?? false;
  const dataDir = options.dataDir ?? join(options.projectRoot, '.venom-cache');
  const logger = options.logger ?? new ConsoleLogger();

  const ownsCache = !options.cache;
  const cache = options.cache ?? new SqliteCache(join(dataDir, 'cache.db'));
  const http = options.http ?? new VenomHttpClient({ offline, logger });

  const config: VenomConfig = {
    offline,
    dataDir,
    ...(options.policy ? { policy: options.policy } : {}),
  };

  return {
    projectRoot: options.projectRoot,
    config,
    http,
    cache,
    logger,
    dispose(): void {
      if (ownsCache && cache instanceof SqliteCache) cache.close();
    },
  };
}
