import type { AuditResult } from '../audit';
import type { Policy } from '../types/policy';

export interface PolicyEvaluation {
  passed: boolean;
  /** Reasons the policy failed (block-level). */
  violations: string[];
  /** Non-blocking concerns (e.g. below min_maintainers). */
  warnings: string[];
}

/**
 * Evaluate an audit against a policy for pass/fail gating (SPEC.md §11). This is
 * the enforcement side of "policy as code" — the CI action turns the result into
 * an exit code. The audit must have been run with the same policy in context so
 * license findings reflect the configured deny list.
 */
export function evaluatePolicy(result: AuditResult, policy: Policy): PolicyEvaluation {
  const violations: string[] = [];
  const warnings: string[] = [];

  if (policy.blockOnSecrets && result.secrets.length > 0) {
    violations.push(`${result.secrets.length} leaked secret(s) detected`);
  }

  if (policy.blockOnKev) {
    const kev = result.vulnerabilities.filter((v) => v.knownExploited);
    if (kev.length > 0) {
      violations.push(
        `${kev.length} actively-exploited (CISA KEV) vulnerability(ies): ${kev.map((v) => v.id).join(', ')}`,
      );
    }
  }

  if (policy.maxCvssSeverity !== undefined) {
    const threshold = policy.maxCvssSeverity;
    const over = result.vulnerabilities.filter((v) => v.cvss && v.cvss.baseScore > threshold);
    if (over.length > 0) {
      violations.push(`${over.length} vulnerability(ies) above CVSS ${threshold}`);
    }
  }

  if (policy.licenseDenylist && policy.licenseDenylist.length > 0) {
    const denied = result.findings.filter((f) => f.ruleId === 'venom/license-denylist');
    if (denied.length > 0) {
      violations.push(`${denied.length} dependency(ies) with a denylisted license`);
    }
  }

  if (policy.minMaintainers !== undefined) {
    const single = result.assessments.filter((a) =>
      a.findings.some(
        (f) => f.ruleId === 'venom/maintainer-risk' && /single maintainer/i.test(f.message),
      ),
    );
    if (single.length > 0) {
      warnings.push(
        `${single.length} production dependency(ies) below ${policy.minMaintainers} maintainer(s)`,
      );
    }
  }

  return { passed: violations.length === 0, violations, warnings };
}
