/**
 * Raised when a network call is attempted in offline mode. Callers should treat
 * this as "degrade gracefully" — serve cached/bundled data or skip the check —
 * never as a crash.
 */
export class OfflineError extends Error {
  constructor(url: string) {
    super(`Offline mode: refused network request to ${url}`);
    this.name = 'OfflineError';
  }
}

/**
 * Raised when code tries to contact a host that is not on Venom's allowlist.
 * This is a hard security control, not a recoverable condition: it means some
 * code path would have leaked data to an unapproved destination, violating the
 * zero-telemetry guarantee (SPEC.md §8). It should surface loudly.
 */
export class DisallowedHostError extends Error {
  readonly host: string;
  constructor(host: string, url: string) {
    super(
      `Refused request to non-allowlisted host "${host}" (${url}). ` +
        `Venom only contacts a fixed set of public APIs; see net/hosts.ts.`,
    );
    this.name = 'DisallowedHostError';
    this.host = host;
  }
}

/** Raised for non-2xx HTTP responses after retries are exhausted. */
export class HttpError extends Error {
  readonly status: number;
  readonly url: string;
  constructor(status: number, url: string, statusText?: string) {
    super(`HTTP ${status}${statusText ? ` ${statusText}` : ''} for ${url}`);
    this.name = 'HttpError';
    this.status = status;
    this.url = url;
  }
}
