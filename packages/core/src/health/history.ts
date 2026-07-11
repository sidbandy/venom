import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import Database from 'better-sqlite3';

export interface ScoreRecord {
  timestamp: string;
  score: number;
  grade: string;
  cveCount: number;
  secretCount: number;
}

/**
 * Local, per-run persistence of the Health Score (SPEC.md §5, Score History).
 * Turns a single snapshot into a trend line — "72 → 68 → 74 over the last month".
 * Fully local SQLite, matching the zero-telemetry design.
 */
export class ScoreHistoryStore {
  readonly #db: Database.Database;
  readonly #insert: Database.Statement<[string, number, string, number, number]>;
  readonly #recent: Database.Statement<[number]>;

  constructor(dbPath: string) {
    if (dbPath !== ':memory:') mkdirSync(dirname(dbPath), { recursive: true });
    this.#db = new Database(dbPath);
    this.#db.pragma('journal_mode = WAL');
    this.#db.exec(`
      CREATE TABLE IF NOT EXISTS score_history (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp    TEXT NOT NULL,
        score        REAL NOT NULL,
        grade        TEXT NOT NULL,
        cve_count    INTEGER NOT NULL,
        secret_count INTEGER NOT NULL
      );
    `);
    this.#insert = this.#db.prepare(
      'INSERT INTO score_history (timestamp, score, grade, cve_count, secret_count) VALUES (?, ?, ?, ?, ?)',
    );
    this.#recent = this.#db.prepare(
      `SELECT timestamp, score, grade, cve_count AS cveCount, secret_count AS secretCount
       FROM score_history ORDER BY id DESC LIMIT ?`,
    );
  }

  record(rec: ScoreRecord): void {
    this.#insert.run(rec.timestamp, rec.score, rec.grade, rec.cveCount, rec.secretCount);
  }

  /** Most recent runs, newest first. */
  recent(limit = 30): ScoreRecord[] {
    return this.#recent.all(limit) as ScoreRecord[];
  }

  close(): void {
    this.#db.close();
  }
}
