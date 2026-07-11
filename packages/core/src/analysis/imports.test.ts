import { describe, expect, it } from 'vitest';
import { extractImports, packageNameOf } from './imports';

describe('extractImports', () => {
  it('finds import, require, dynamic import, and re-export specifiers', () => {
    const code = `
      import a from 'foo';
      import { b } from '@scope/bar';
      const c = require('baz');
      import('qux');
      export * from 'quux';
      import rel from './local';
    `;
    const found = extractImports(code);
    expect(found).toEqual(
      expect.arrayContaining(['foo', '@scope/bar', 'baz', 'qux', 'quux', './local']),
    );
  });

  it('returns nothing for unparseable input', () => {
    expect(extractImports('this is (((not valid')).toEqual([]);
  });
});

describe('packageNameOf', () => {
  it('resolves specifiers to package names', () => {
    expect(packageNameOf('foo')).toBe('foo');
    expect(packageNameOf('foo/sub/path')).toBe('foo');
    expect(packageNameOf('@scope/pkg')).toBe('@scope/pkg');
    expect(packageNameOf('@scope/pkg/deep')).toBe('@scope/pkg');
  });
  it('ignores relative paths and node builtins', () => {
    expect(packageNameOf('./local')).toBeNull();
    expect(packageNameOf('/abs')).toBeNull();
    expect(packageNameOf('node:fs')).toBeNull();
  });
});
