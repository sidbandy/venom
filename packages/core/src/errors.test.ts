import { describe, expect, it } from 'vitest';
import { VenomError } from './errors';
import { OfflineError, DisallowedHostError, HttpError } from './net/errors';
import { TarballSecurityError } from './extract/tarball';
import { NoSupportedLockfileError } from './inventory/inventory';

describe('VenomError taxonomy', () => {
  it('every engine error extends VenomError and carries a stable code', () => {
    const cases: Array<[VenomError, string]> = [
      [new OfflineError('https://x'), 'OFFLINE'],
      [new DisallowedHostError('evil.com', 'https://evil.com'), 'DISALLOWED_HOST'],
      [new HttpError(500, 'https://x'), 'HTTP_ERROR'],
      [new TarballSecurityError('zip slip'), 'TARBALL_SECURITY'],
      [new NoSupportedLockfileError('/x'), 'NO_LOCKFILE'],
    ];
    for (const [err, code] of cases) {
      expect(err).toBeInstanceOf(VenomError);
      expect(err).toBeInstanceOf(Error);
      expect(err.code).toBe(code);
    }
  });
});
