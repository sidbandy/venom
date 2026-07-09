import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import Database from 'better-sqlite3';
import type { Cache } from '../types/context';

interface CacheRow {
  value: string;
  expires_at: number | null;
}

/**
 * A namespaced key/value cache with per-entry TTLs, backed by local SQLite
 * (`better-sqlite3`). Used to memoize idempotent network lookups (registry
 * metadata, OSV results, KEV catalog) so runs are fast and repeatable, and so
 * offline mode can serve previously-fetched data. No server, fully local — in
 * keeping with the zero-telemetry design (SPEC.md §9.2).
 */
export class SqliteCache implements Cache {
  readonly #db: Database.Database;
  readonly #getStmt: Database.Statement<[string, string]>;
  readonly #setStmt: Database.Statement<[string, string, string, number | null]>;
  readonly #delStmt: Database.Statement<[string, string]>;

  /**
   * @param dbPath Filesystem path for the cache database, or `:memory:` for an
   *   ephemeral in-memory cache (used in tests).
   */
  constructor(dbPath: string) {
    if (dbPath !== ':memory:') {
      mkdirSync(dirname(dbPath), { recursive: true });
    }
    this.#db = new Database(dbPath);
    this.#db.pragma('journal_mode = WAL');
    this.#db.exec(`
      CREATE TABLE IF NOT EXISTS cache (
        namespace  TEXT NOT NULL,
        key        TEXT NOT NULL,
        value      TEXT NOT NULL,
        expires_at INTEGER,
        PRIMARY KEY (namespace, key)
      );
    `);
    this.#getStmt = this.#db.prepare(
      'SELECT value, expires_at FROM cache WHERE namespace = ? AND key = ?',
    );
    this.#setStmt = this.#db.prepare(
      `INSERT INTO cache (namespace, key, value, expires_at) VALUES (?, ?, ?, ?)
       ON CONFLICT(namespace, key) DO UPDATE SET value = excluded.value, expires_at = excluded.expires_at`,
    );
    this.#delStmt = this.#db.prepare('DELETE FROM cache WHERE namespace = ? AND key = ?');
  }

  get<T>(namespace: string, key: string): T | undefined {
    const row = this.#getStmt.get(namespace, key) as CacheRow | undefined;
    if (!row) return undefined;
    if (row.expires_at !== null && Date.now() > row.expires_at) {
      // Lazily evict expired entries on read.
      this.#delStmt.run(namespace, key);
      return undefined;
    }
    return JSON.parse(row.value) as T;
  }

  set<T>(namespace: string, key: string, value: T, ttlMs?: number): void {
    const expiresAt = ttlMs !== undefined ? Date.now() + ttlMs : null;
    this.#setStmt.run(namespace, key, JSON.stringify(value), expiresAt);
  }

  delete(namespace: string, key: string): void {
    this.#delStmt.run(namespace, key);
  }

  /** Remove every expired entry. Optional housekeeping; reads self-evict anyway. */
  purgeExpired(): void {
    this.#db
      .prepare('DELETE FROM cache WHERE expires_at IS NOT NULL AND expires_at < ?')
      .run(Date.now());
  }

  close(): void {
    this.#db.close();
  }
}
