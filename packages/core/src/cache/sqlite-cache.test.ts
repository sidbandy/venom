import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SqliteCache } from './sqlite-cache';

describe('SqliteCache', () => {
  let cache: SqliteCache;

  beforeEach(() => {
    cache = new SqliteCache(':memory:');
  });

  afterEach(() => {
    cache.close();
    vi.useRealTimers();
  });

  it('stores and retrieves JSON values by namespace + key', () => {
    cache.set('osv', 'lodash@4.17.21', { vulns: ['CVE-1'] });
    expect(cache.get('osv', 'lodash@4.17.21')).toEqual({ vulns: ['CVE-1'] });
  });

  it('returns undefined for a miss', () => {
    expect(cache.get('osv', 'nope')).toBeUndefined();
  });

  it('isolates identical keys across namespaces', () => {
    cache.set('osv', 'k', 1);
    cache.set('npm', 'k', 2);
    expect(cache.get('osv', 'k')).toBe(1);
    expect(cache.get('npm', 'k')).toBe(2);
  });

  it('overwrites an existing key', () => {
    cache.set('npm', 'lodash', { v: 1 });
    cache.set('npm', 'lodash', { v: 2 });
    expect(cache.get('npm', 'lodash')).toEqual({ v: 2 });
  });

  it('expires entries after their TTL', () => {
    vi.useFakeTimers();
    cache.set('osv', 'k', 'value', 1000);
    expect(cache.get('osv', 'k')).toBe('value');
    vi.advanceTimersByTime(1001);
    expect(cache.get('osv', 'k')).toBeUndefined();
  });

  it('treats a missing TTL as non-expiring', () => {
    vi.useFakeTimers();
    cache.set('osv', 'k', 'forever');
    vi.advanceTimersByTime(10 ** 9);
    expect(cache.get('osv', 'k')).toBe('forever');
  });

  it('deletes entries', () => {
    cache.set('npm', 'k', 1);
    cache.delete('npm', 'k');
    expect(cache.get('npm', 'k')).toBeUndefined();
  });
});
