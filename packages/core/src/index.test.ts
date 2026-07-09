import { describe, expect, it } from 'vitest';
import { VERSION } from './index';

describe('@venom/core', () => {
  it('exposes a version string', () => {
    expect(VERSION).toMatch(/^\d+\.\d+\.\d+$/);
  });
});
