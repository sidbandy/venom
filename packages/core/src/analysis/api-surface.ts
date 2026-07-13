import type { AuditResult } from '../audit';
import type { SecretKind } from '../types/secret';

/**
 * API/SDK-dependency awareness (future.md, and the "Fidolio" use case). A project
 * that leans on many third-party APIs pulls in the matching client SDKs — Venom
 * already vets those packages and catches their leaked keys; this groups it all by
 * the external *service* each SDK talks to, so you see your API surface at a
 * glance: which services you depend on, whether their SDKs are outdated or carry
 * CVEs, and whether their credentials have leaked.
 *
 * (Live endpoint uptime/health is intentionally out of scope — that's runtime
 * monitoring, a different product.)
 */

/** Exact npm package name → external service. */
const SDK_SERVICES: Record<string, string> = {
  stripe: 'Stripe',
  '@stripe/stripe-js': 'Stripe',
  openai: 'OpenAI',
  '@anthropic-ai/sdk': 'Anthropic',
  twilio: 'Twilio',
  '@sendgrid/mail': 'SendGrid',
  googleapis: 'Google',
  firebase: 'Firebase',
  'firebase-admin': 'Firebase',
  '@supabase/supabase-js': 'Supabase',
  'aws-sdk': 'AWS',
  mongodb: 'MongoDB',
  mongoose: 'MongoDB',
  pg: 'PostgreSQL',
  mysql2: 'MySQL',
  redis: 'Redis',
  ioredis: 'Redis',
  algoliasearch: 'Algolia',
  plaid: 'Plaid',
  'shopify-api-node': 'Shopify',
  mailchimp: 'Mailchimp',
  'posthog-node': 'PostHog',
  mixpanel: 'Mixpanel',
  '@notionhq/client': 'Notion',
  'discord.js': 'Discord',
  telegraf: 'Telegram',
  octokit: 'GitHub',
};

/** Scoped-package prefix → service (covers families like @aws-sdk/client-*). */
const SDK_PREFIXES: Array<[string, string]> = [
  ['@aws-sdk/', 'AWS'],
  ['@octokit/', 'GitHub'],
  ['@google-cloud/', 'Google Cloud'],
  ['@slack/', 'Slack'],
  ['@sentry/', 'Sentry'],
  ['@shopify/', 'Shopify'],
  ['@azure/', 'Azure'],
];

/** Secret kind → the service its credential belongs to. */
const SECRET_SERVICE: Partial<Record<SecretKind, string>> = {
  'stripe-secret': 'Stripe',
  'google-api-key': 'Google',
  'slack-token': 'Slack',
  'github-pat': 'GitHub',
  'gitlab-pat': 'GitLab',
  'aws-access-key': 'AWS',
  'aws-secret-key': 'AWS',
};

export interface ApiSdkEntry {
  service: string;
  package: string;
  version: string;
  /** An update is available (any tier). */
  outdated: boolean;
  /** A major version behind (the update is `risky`). */
  majorBehind: boolean;
  /** CVE/advisory ids affecting this SDK version. */
  cves: string[];
}

export interface ApiSurface {
  entries: ApiSdkEntry[];
  /** Count of leaked credentials per external service. */
  leakedKeysByService: Record<string, number>;
}

/** Which external service, if any, does this package's SDK belong to? */
export function serviceForPackage(name: string): string | undefined {
  if (SDK_SERVICES[name]) return SDK_SERVICES[name];
  for (const [prefix, service] of SDK_PREFIXES) {
    if (name.startsWith(prefix)) return service;
  }
  return undefined;
}

/** Cross-reference an audit result into a per-service API-surface report. */
export function analyzeApiSurface(result: AuditResult): ApiSurface {
  const vulnByName = new Map<string, string[]>();
  for (const v of result.vulnerabilities) {
    const id = v.aliases.find((a) => a.startsWith('CVE')) ?? v.id;
    const list = vulnByName.get(v.affected.name);
    if (list) list.push(id);
    else vulnByName.set(v.affected.name, [id]);
  }
  const planByName = new Map(result.updatePlan.map((e) => [e.current.name, e]));

  const entries: ApiSdkEntry[] = [];
  const seen = new Set<string>();
  for (const node of result.graph.nodes.values()) {
    const service = serviceForPackage(node.ref.name);
    if (!service || seen.has(node.ref.name)) continue;
    seen.add(node.ref.name);
    const plan = planByName.get(node.ref.name);
    entries.push({
      service,
      package: node.ref.name,
      version: node.ref.version,
      outdated: Boolean(plan),
      majorBehind: plan?.tier === 'risky',
      cves: vulnByName.get(node.ref.name) ?? [],
    });
  }
  entries.sort((a, b) => a.service.localeCompare(b.service) || a.package.localeCompare(b.package));

  const leakedKeysByService: Record<string, number> = {};
  for (const secret of result.secrets) {
    const service = SECRET_SERVICE[secret.kind];
    if (service) leakedKeysByService[service] = (leakedKeysByService[service] ?? 0) + 1;
  }

  return { entries, leakedKeysByService };
}
