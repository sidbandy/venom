import type { Logger } from './types/context';

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const ORDER: Record<LogLevel, number> = { debug: 0, info: 1, warn: 2, error: 3 };

/**
 * Default logger. Writes to **stderr** for every level so that stdout stays
 * reserved for machine-readable output (SBOM JSON, SARIF, `--json`).
 */
export class ConsoleLogger implements Logger {
  readonly #min: number;
  constructor(level: LogLevel = 'info') {
    this.#min = ORDER[level];
  }
  #log(level: LogLevel, msg: string, args: unknown[]): void {
    if (ORDER[level] < this.#min) return;
    process.stderr.write(
      `[venom:${level}] ${msg}${args.length ? ' ' + args.map(String).join(' ') : ''}\n`,
    );
  }
  debug(msg: string, ...args: unknown[]): void {
    this.#log('debug', msg, args);
  }
  info(msg: string, ...args: unknown[]): void {
    this.#log('info', msg, args);
  }
  warn(msg: string, ...args: unknown[]): void {
    this.#log('warn', msg, args);
  }
  error(msg: string, ...args: unknown[]): void {
    this.#log('error', msg, args);
  }
}

/** A logger that discards everything — handy in tests and library embeddings. */
export const noopLogger: Logger = {
  debug() {},
  info() {},
  warn() {},
  error() {},
};
