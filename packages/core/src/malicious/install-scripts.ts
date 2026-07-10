/**
 * Install-script inspection (SPEC.md §4 M3). Package managers run lifecycle
 * scripts automatically on install — the single most common malware vector. Venom
 * reads these scripts as **plain text** (never executing them) and pattern-matches
 * against known-dangerous constructs: remote downloads, pipes to a shell, inline
 * code execution, base64 payloads, and environment/secret exfiltration.
 */

/** npm lifecycle scripts that run automatically around install. */
export const INSTALL_LIFECYCLE = new Set([
  'preinstall',
  'install',
  'postinstall',
  'preuninstall',
  'postuninstall',
  'prepare',
]);

interface DangerPattern {
  label: string;
  re: RegExp;
}

// Deliberately simple, anchored patterns (no catastrophic backtracking).
const PATTERNS: DangerPattern[] = [
  { label: 'downloads remote content (curl/wget)', re: /\b(curl|wget)\b/ },
  { label: 'pipes downloaded content into a shell', re: /\|\s*(sh|bash|zsh|node|python3?)\b/ },
  { label: 'inline code execution', re: /\b(node|python3?|ruby|perl)\s+-e\b/ },
  { label: 'base64-decoded payload', re: /base64\s+-{1,2}d|from\(['"][^'"]*['"],\s*['"]base64/ },
  {
    label: 'reads environment/secrets',
    re: /process\.env|\$\{?(NPM_TOKEN|AWS_|GITHUB_TOKEN|SECRET)/,
  },
  { label: 'raw TCP / reverse shell', re: /\/dev\/tcp\/|\bnc\b\s+-|\bnetcat\b/ },
  { label: 'contacts a raw IP address', re: /https?:\/\/\d{1,3}(\.\d{1,3}){3}/ },
  { label: 'destructive filesystem operation', re: /\brm\s+-rf\s+[~/]/ },
  { label: 'marks a file executable', re: /\bchmod\s+\+x\b/ },
];

export interface InstallScriptSignal {
  /** The lifecycle hook (e.g. `postinstall`). */
  script: string;
  command: string;
  /** Human-readable descriptions of what matched. */
  reasons: string[];
}

/**
 * Inspect a package's declared scripts. Only install-lifecycle hooks are examined
 * (those run without the user asking). Returns one signal per hook that contains a
 * dangerous construct; hooks that merely exist without dangerous content are not
 * flagged here (their mere presence is surfaced separately as lower-severity info).
 */
export function inspectInstallScripts(
  scripts: Record<string, string> | undefined,
): InstallScriptSignal[] {
  if (!scripts) return [];
  const signals: InstallScriptSignal[] = [];
  for (const [name, command] of Object.entries(scripts)) {
    if (!INSTALL_LIFECYCLE.has(name) || typeof command !== 'string') continue;
    const reasons = PATTERNS.filter((p) => p.re.test(command)).map((p) => p.label);
    if (reasons.length > 0) signals.push({ script: name, command, reasons });
  }
  return signals;
}

/** True if the package declares any auto-running install lifecycle script. */
export function hasInstallLifecycle(scripts: Record<string, string> | undefined): boolean {
  if (!scripts) return false;
  return Object.keys(scripts).some((name) => INSTALL_LIFECYCLE.has(name));
}
