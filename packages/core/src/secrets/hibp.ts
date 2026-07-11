import { createHash } from 'node:crypto';
import type { ScanContext } from '../types/context';
import { OfflineError } from '../net/errors';

const HIBP_RANGE = 'https://api.pwnedpasswords.com/range/';
const TTL_MS = 7 * 24 * 60 * 60 * 1000;

export interface BreachResult {
  breached: boolean;
  count: number;
}

/**
 * Check whether a password appears in known public breaches via Have I Been
 * Pwned's k-anonymity range API (SPEC.md §4 M4) — **without ever sending the
 * password**. The password is SHA-1'd locally; only the first 5 hex characters of
 * the hash leave the machine. HIBP returns every breached suffix sharing that
 * prefix, and we match the full hash locally. Responses are cached per prefix, so
 * many passwords sharing a prefix cost a single request. `Add-Padding` requests
 * padded responses so the reply size doesn't leak how many suffixes matched.
 */
export async function checkPassword(password: string, ctx: ScanContext): Promise<BreachResult> {
  const sha1 = createHash('sha1').update(password, 'utf8').digest('hex').toUpperCase();
  const prefix = sha1.slice(0, 5);
  const suffix = sha1.slice(5);

  let body = ctx.cache.get<string>('hibp', prefix);
  if (body === undefined) {
    try {
      body = await ctx.http.getText(`${HIBP_RANGE}${prefix}`, {
        headers: { 'Add-Padding': 'true' },
      });
      ctx.cache.set('hibp', prefix, body, TTL_MS);
    } catch (err) {
      if (!(err instanceof OfflineError)) {
        ctx.logger.warn(`HIBP: range lookup failed: ${String(err)}`);
      }
      return { breached: false, count: 0 };
    }
  }

  for (const line of body.split('\n')) {
    const sep = line.indexOf(':');
    if (sep === -1) continue;
    if (line.slice(0, sep).trim().toUpperCase() === suffix) {
      const count = Number.parseInt(line.slice(sep + 1).trim(), 10);
      // Padded (fake) entries carry a count of 0; a real hit has count > 0.
      if (count > 0) return { breached: true, count };
    }
  }
  return { breached: false, count: 0 };
}
