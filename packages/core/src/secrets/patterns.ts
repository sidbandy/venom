import type { SecretKind } from '../types/secret';

export interface SecretPattern {
  id: string;
  kind: SecretKind;
  description: string;
  /**
   * Global regex. If it has a capture group, group 1 is treated as the secret
   * value (for redaction / breach checks); otherwise the whole match is the value.
   * Patterns are anchored/bounded to avoid catastrophic backtracking (ReDoS).
   */
  regex: RegExp;
  /** Minimum Shannon entropy of the value to count — filters obvious placeholders. */
  minEntropy?: number;
  /** Eligible for a Have I Been Pwned breach check (i.e. it's a password). */
  password?: boolean;
}

/**
 * Curated credential patterns (SPEC.md §4 M4). Each identifies not just *that*
 * something is a secret but *what kind*. This is a strong-signal core set;
 * expanding toward the 100+ that tools like gitleaks ship is tracked in future.md.
 */
export const SECRET_PATTERNS: readonly SecretPattern[] = [
  {
    id: 'aws-access-key',
    kind: 'aws-access-key',
    description: 'AWS access key ID',
    regex: /\b((?:AKIA|ASIA|AGPA|AIDA)[A-Z0-9]{16})\b/g,
  },
  {
    id: 'aws-secret-key',
    kind: 'aws-secret-key',
    description: 'AWS secret access key',
    regex: /aws_?secret_?access_?key\s*[=:]\s*["']?([A-Za-z0-9/+]{40})["']?/gi,
    minEntropy: 3.5,
  },
  {
    id: 'github-pat',
    kind: 'github-pat',
    description: 'GitHub personal access token',
    regex: /\b(gh[posru]_[A-Za-z0-9]{36})\b/g,
  },
  {
    id: 'github-fine-grained-pat',
    kind: 'github-pat',
    description: 'GitHub fine-grained personal access token',
    regex: /\b(github_pat_[A-Za-z0-9_]{82})\b/g,
  },
  {
    id: 'gitlab-pat',
    kind: 'gitlab-pat',
    description: 'GitLab personal access token',
    regex: /\b(glpat-[A-Za-z0-9_-]{20})\b/g,
  },
  {
    id: 'stripe-secret',
    kind: 'stripe-secret',
    description: 'Stripe live secret/restricted key',
    regex: /\b([rs]k_live_[A-Za-z0-9]{24})\b/g,
  },
  {
    id: 'slack-token',
    kind: 'slack-token',
    description: 'Slack token',
    regex: /\b(xox[baprs]-[A-Za-z0-9-]{10,48})\b/g,
  },
  {
    id: 'slack-webhook',
    kind: 'slack-token',
    description: 'Slack incoming webhook URL',
    regex:
      /(https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_]+\/B[A-Za-z0-9_]+\/[A-Za-z0-9_]{16,})/g,
  },
  {
    id: 'google-api-key',
    kind: 'google-api-key',
    description: 'Google API key',
    regex: /\b(AIza[0-9A-Za-z_-]{35})\b/g,
  },
  {
    id: 'openai-key',
    kind: 'generic-high-entropy',
    description: 'OpenAI API key',
    regex: /\b(sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,})\b/g,
  },
  {
    id: 'anthropic-key',
    kind: 'generic-high-entropy',
    description: 'Anthropic API key',
    regex: /\b(sk-ant-[A-Za-z0-9_-]{24,})\b/g,
  },
  {
    id: 'npm-token',
    kind: 'generic-high-entropy',
    description: 'npm access token',
    regex: /\b(npm_[A-Za-z0-9]{36})\b/g,
  },
  {
    id: 'pypi-token',
    kind: 'generic-high-entropy',
    description: 'PyPI upload token',
    regex: /\b(pypi-AgEIcHlwaS[A-Za-z0-9_-]{16,})\b/g,
  },
  {
    id: 'sendgrid-key',
    kind: 'generic-high-entropy',
    description: 'SendGrid API key',
    regex: /\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b/g,
  },
  {
    id: 'twilio-api-key',
    kind: 'generic-high-entropy',
    description: 'Twilio API key SID',
    regex: /\b(SK[0-9a-fA-F]{32})\b/g,
  },
  {
    id: 'digitalocean-token',
    kind: 'generic-high-entropy',
    description: 'DigitalOcean personal access token',
    regex: /\b(dop_v1_[a-f0-9]{64})\b/g,
  },
  {
    id: 'shopify-token',
    kind: 'generic-high-entropy',
    description: 'Shopify access token',
    regex: /\b(shp(?:at|ss|ca|pa)_[a-fA-F0-9]{32})\b/g,
  },
  {
    id: 'square-access-token',
    kind: 'generic-high-entropy',
    description: 'Square access token',
    regex: /\b(sq0atp-[A-Za-z0-9_-]{22}|EAAA[A-Za-z0-9_-]{60})\b/g,
  },
  {
    id: 'postman-key',
    kind: 'generic-high-entropy',
    description: 'Postman API key',
    regex: /\b(PMAK-[a-f0-9]{24}-[a-f0-9]{34})\b/g,
  },
  {
    id: 'newrelic-key',
    kind: 'generic-high-entropy',
    description: 'New Relic API key',
    regex: /\b(NRAK-[A-Z0-9]{27})\b/g,
  },
  {
    id: 'databricks-token',
    kind: 'generic-high-entropy',
    description: 'Databricks personal access token',
    regex: /\b(dapi[a-f0-9]{32})\b/g,
  },
  {
    id: 'doppler-token',
    kind: 'generic-high-entropy',
    description: 'Doppler token',
    regex: /\b(dp\.(?:pt|st|sa|ct)\.[A-Za-z0-9]{40,44})\b/g,
  },
  {
    id: 'huggingface-token',
    kind: 'generic-high-entropy',
    description: 'Hugging Face access token',
    regex: /\b(hf_[A-Za-z0-9]{34})\b/g,
  },
  {
    id: 'linear-key',
    kind: 'generic-high-entropy',
    description: 'Linear API key',
    regex: /\b(lin_api_[A-Za-z0-9]{40})\b/g,
  },
  {
    id: 'figma-token',
    kind: 'generic-high-entropy',
    description: 'Figma personal access token',
    regex: /\b(figd_[A-Za-z0-9_-]{40,})\b/g,
  },
  {
    id: 'telegram-bot-token',
    kind: 'generic-high-entropy',
    description: 'Telegram bot token',
    regex: /\b(\d{8,10}:AA[A-Za-z0-9_-]{32,33})\b/g,
  },
  {
    id: 'mailchimp-key',
    kind: 'generic-high-entropy',
    description: 'Mailchimp API key',
    regex: /\b([a-f0-9]{32}-us\d{1,2})\b/g,
  },
  {
    id: 'terraform-token',
    kind: 'generic-high-entropy',
    description: 'Terraform Cloud/Enterprise token',
    regex: /\b([A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_-]{60,})\b/g,
  },
  {
    id: 'planetscale-token',
    kind: 'generic-high-entropy',
    description: 'PlanetScale token',
    regex: /\b(pscale_(?:pw|tkn)_[A-Za-z0-9_.-]{32,})\b/g,
  },
  {
    id: 'supabase-token',
    kind: 'generic-high-entropy',
    description: 'Supabase service token',
    regex: /\b(sbp_[a-f0-9]{40})\b/g,
  },
  {
    id: 'sentry-dsn',
    kind: 'generic-high-entropy',
    description: 'Sentry DSN (contains a secret key)',
    regex: /(https:\/\/[a-f0-9]{32}@[a-z0-9.-]+\.ingest\.sentry\.io\/\d+)/g,
  },
  {
    id: 'azure-storage-key',
    kind: 'generic-high-entropy',
    description: 'Azure Storage account key',
    regex: /AccountKey=([A-Za-z0-9+/]{86}==)/g,
  },
  {
    id: 'rubygems-key',
    kind: 'generic-high-entropy',
    description: 'RubyGems API key',
    regex: /\b(rubygems_[a-f0-9]{48})\b/g,
  },
  {
    id: 'pulumi-token',
    kind: 'generic-high-entropy',
    description: 'Pulumi access token',
    regex: /\b(pul-[a-f0-9]{40})\b/g,
  },
  {
    id: 'grafana-token',
    kind: 'generic-high-entropy',
    description: 'Grafana Cloud token',
    regex: /\b(glc_[A-Za-z0-9+/=]{32,})\b/g,
  },
  {
    id: 'openai-project-key',
    kind: 'generic-high-entropy',
    description: 'OpenAI project API key',
    regex: /\b(sk-proj-[A-Za-z0-9_-]{40,})\b/g,
  },
  {
    id: 'jwt',
    kind: 'jwt',
    description: 'JSON Web Token',
    regex: /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g,
  },
  {
    id: 'private-key',
    kind: 'private-key',
    description: 'Private key block',
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g,
  },
  {
    id: 'basic-auth-url',
    kind: 'generic-password',
    description: 'Credentials embedded in a URL (incl. DB connection strings)',
    regex: /\b[a-z][a-z0-9+.-]*:\/\/[^\s:@/]+:([^\s:@/]{3,})@/gi,
    password: true,
  },
  {
    id: 'generic-password',
    kind: 'generic-password',
    description: 'Hardcoded password assignment',
    regex: /(?:password|passwd|pwd)\s*[=:]\s*["']([^"'\n]{6,64})["']/gi,
    password: true,
    minEntropy: 2.5,
  },
  {
    id: 'generic-secret',
    kind: 'generic-high-entropy',
    description: 'Hardcoded API key / secret assignment',
    regex:
      /(?:api[_-]?key|secret|access[_-]?token|auth[_-]?token)\s*[=:]\s*["']([A-Za-z0-9_\-.]{16,64})["']/gi,
    minEntropy: 3.2,
  },
];
