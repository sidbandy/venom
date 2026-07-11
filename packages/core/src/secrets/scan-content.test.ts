import { describe, expect, it } from 'vitest';
import { scanContent } from './scan-content';

// Fixture tokens are assembled from parts so this source file itself contains no
// literal secret (keeps GitHub push-protection and Venom's own scan clean); the
// runtime values are still the full, detectable tokens.
// Non-canonical, assembled-from-parts fixtures: still match the detectors, but are
// neither on the example allowlist nor a literal secret in this committed file.
const AWS_KEY = `AKIA${'ROSFODNN7TESTKEY'}`;
const AWS_SECRET = `${'aB3dE6gH9jK2mN5pQ8rS'}${'1tU4vW7xY0zA1bC2dE3f'}`;
const GH_PAT = `ghp_${'1234567890abcdefghijklmnopqrstuvwxyz'}`;
const STRIPE_KEY = `sk_live_${'abcdefghijklmnopqrstuvwx'}`;

describe('scanContent', () => {
  it('detects a variety of credential types with redacted previews', () => {
    const text = [
      `const awsKey = "${AWS_KEY}";`,
      `aws_secret_access_key = "${AWS_SECRET}"`,
      `GITHUB_TOKEN=${GH_PAT}`,
      `stripe = "${STRIPE_KEY}"`,
      'const db = "postgres://admin:sup3rs3cret@db.example.com:5432/app";',
    ].join('\n');

    const found = scanContent(text);
    const ids = found.map((f) => f.patternId);
    expect(ids).toEqual(
      expect.arrayContaining([
        'aws-access-key',
        'aws-secret-key',
        'github-pat',
        'stripe-secret',
        'basic-auth-url',
      ]),
    );

    // Previews must be redacted — the raw secret must never appear in the preview.
    const aws = found.find((f) => f.patternId === 'aws-access-key')!;
    expect(aws.preview).not.toBe(aws.value);
    expect(aws.preview).toMatch(/\*/);
    expect(aws.line).toBe(1);
  });

  it('captures the password from a basic-auth URL and marks it breach-checkable', () => {
    const found = scanContent('url = "https://user:hunter2pass@host/path"');
    const cred = found.find((f) => f.patternId === 'basic-auth-url')!;
    expect(cred.value).toBe('hunter2pass');
    expect(cred.password).toBe(true);
  });

  it('ignores low-entropy placeholders', () => {
    expect(scanContent('password = "changeme"')).toHaveLength(0);
    expect(scanContent('api_key = "your-api-key-here"')).toHaveLength(0);
  });

  it('ignores canonical documentation/example credentials', () => {
    // AWS's own documented example key appears in countless docs/tutorials.
    expect(scanContent('const k = "AKIAIOSFODNN7EXAMPLE";')).toHaveLength(0);
  });

  it('skips binary content', () => {
    const binary = `AKIAIOSFODNN7EXAMPLE${String.fromCharCode(0)}rest`;
    expect(scanContent(binary)).toHaveLength(0);
  });
});
