import type { Finding, FindingLevel } from '../types/finding';

/**
 * SARIF 2.1.0 output (SPEC.md §4 M5, §12). Emitting SARIF is what lets GitHub,
 * GitLab, and Azure DevOps render Venom's findings natively in their security
 * tabs. Because every module already emits the SARIF-shaped {@link Finding}, this
 * is a mechanical projection with no per-module special-casing.
 */

export interface SarifLog {
  $schema: string;
  version: '2.1.0';
  runs: SarifRun[];
}

interface SarifRun {
  tool: {
    driver: {
      name: string;
      version: string;
      informationUri: string;
      rules: SarifRule[];
    };
  };
  results: SarifResult[];
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  defaultConfiguration: { level: FindingLevel };
  properties: { tags: string[]; 'security-severity': string };
}

interface SarifResult {
  ruleId: string;
  level: FindingLevel;
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
      region?: { startLine: number; endLine?: number };
    };
  }>;
  partialFingerprints: Record<string, string>;
  properties?: Record<string, unknown>;
}

export interface SarifOptions {
  toolVersion?: string;
}

/** GitHub reads `security-severity` (a CVSS-like 0–10) off the rule to sort/badge. */
const SECURITY_SEVERITY: Record<FindingLevel, string> = {
  error: '8.0',
  warning: '4.0',
  note: '1.0',
};

export function toSarif(findings: Finding[], options: SarifOptions = {}): SarifLog {
  const version = options.toolVersion ?? '0.1.0';

  // One rule per distinct ruleId, described by the first finding that used it.
  const rules = new Map<string, SarifRule>();
  for (const f of findings) {
    if (rules.has(f.ruleId)) continue;
    rules.set(f.ruleId, {
      id: f.ruleId,
      name: f.ruleId,
      shortDescription: { text: f.title },
      defaultConfiguration: { level: f.level },
      properties: { tags: [f.category], 'security-severity': SECURITY_SEVERITY[f.level] },
    });
  }

  const results: SarifResult[] = findings.map((f) => ({
    ruleId: f.ruleId,
    level: f.level,
    message: { text: f.message },
    locations: f.locations.map((loc) => ({
      physicalLocation: {
        artifactLocation: { uri: loc.uri },
        ...(loc.startLine
          ? {
              region: {
                startLine: loc.startLine,
                ...(loc.endLine ? { endLine: loc.endLine } : {}),
              },
            }
          : {}),
      },
    })),
    partialFingerprints: { venomFingerprint: f.fingerprint },
    ...(f.properties ? { properties: f.properties } : {}),
  }));

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Venom',
            version,
            informationUri: 'https://github.com/sidbandy/venom',
            rules: [...rules.values()],
          },
        },
        results,
      },
    ],
  };
}

/** Serialize a SARIF log to pretty JSON. */
export function generateSarif(findings: Finding[], options?: SarifOptions): string {
  return JSON.stringify(toSarif(findings, options), null, 2);
}
