import { levenshtein } from './levenshtein';

export interface TyposquatResult {
  suspicious: boolean;
  /** The popular package this name is suspiciously close to. */
  target?: string;
  /** Edit distance to that target (1 or 2 when suspicious). */
  distance?: number;
}

export interface TyposquatOptions {
  /** Maximum edit distance to consider a typosquat. Default 2. */
  maxDistance?: number;
  /** Ignore popular targets shorter than this (avoids noise on tiny names). Default 5. */
  minTargetLength?: number;
  /**
   * A distance of 2 is only allowed when the shorter of the two names is at least
   * this long. Short names within distance 2 are almost always coincidental
   * collisions (`acorn`↔`cors`), not typosquats; a distance-2 typo is meaningful
   * mainly in longer names (`requests`↔`reqeusts`). Default 7.
   */
  distance2MinLength?: number;
}

/**
 * Typosquat detection (SPEC.md §4 M3): flag an unknown package name that sits a
 * tiny edit distance from a hugely popular one (`reqeusts` vs `requests`). A name
 * that *is* itself on the popular list is never a typosquat.
 *
 * The allowed edit distance scales with name length to avoid the classic
 * false-positive problem — legitimate short names are frequently within two edits
 * of some popular name purely by chance.
 */
export function detectTyposquat(
  name: string,
  popular: Iterable<string>,
  options: TyposquatOptions = {},
): TyposquatResult {
  const maxDistance = options.maxDistance ?? 2;
  const minTargetLength = options.minTargetLength ?? 5;
  const distance2MinLength = options.distance2MinLength ?? 7;
  const lower = name.toLowerCase();

  let best: { target: string; distance: number } | undefined;
  for (const candidate of popular) {
    const target = candidate.toLowerCase();
    if (target === lower) return { suspicious: false }; // this IS the popular package
    if (target.length < minTargetLength) continue;
    if (Math.abs(target.length - lower.length) > maxDistance) continue;

    // Allow distance 2 only for sufficiently long names; otherwise distance 1.
    const allowed = Math.min(
      maxDistance,
      Math.min(target.length, lower.length) >= distance2MinLength ? 2 : 1,
    );
    const distance = levenshtein(lower, target, allowed);
    if (distance >= 1 && distance <= allowed && (!best || distance < best.distance)) {
      best = { target: candidate, distance };
    }
  }

  return best ? { suspicious: true, ...best } : { suspicious: false };
}
