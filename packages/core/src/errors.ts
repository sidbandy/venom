/**
 * Base class for every error the engine throws. A stable `code` lets callers
 * (the CLI, CI action, plugin) map failures to consistent exit statuses and
 * messages without string-matching. All engine errors extend this.
 */
export class VenomError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = 'VenomError';
    this.code = code;
  }
}

/** Stable error codes. */
export type VenomErrorCode =
  'OFFLINE' | 'DISALLOWED_HOST' | 'HTTP_ERROR' | 'TARBALL_SECURITY' | 'NO_LOCKFILE';
