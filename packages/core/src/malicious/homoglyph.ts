/**
 * Homoglyph detection (SPEC.md §4 M3). Characters from different alphabets can be
 * visually identical — Latin `a` (U+0061) and Cyrillic `а` (U+0430) render the
 * same. An attacker can register a name that *looks* legitimate but isn't. We flag
 * any package name mixing Unicode scripts, or containing non-ASCII characters at
 * all (registry naming policies are ASCII, so non-ASCII is inherently suspect).
 */

const SCRIPTS: Array<{ name: string; re: RegExp }> = [
  { name: 'Latin', re: /\p{Script=Latin}/u },
  { name: 'Cyrillic', re: /\p{Script=Cyrillic}/u },
  { name: 'Greek', re: /\p{Script=Greek}/u },
  { name: 'Armenian', re: /\p{Script=Armenian}/u },
  { name: 'Hebrew', re: /\p{Script=Hebrew}/u },
  { name: 'Arabic', re: /\p{Script=Arabic}/u },
];

export interface HomoglyphResult {
  suspicious: boolean;
  /** Distinct Unicode scripts found among the name's letters. */
  scripts: string[];
  hasNonAscii: boolean;
  reason?: string;
}

export function detectHomoglyphs(name: string): HomoglyphResult {
  const hasNonAscii = [...name].some((ch) => ch.codePointAt(0)! > 127);
  const scripts = new Set<string>();
  for (const ch of name) {
    for (const script of SCRIPTS) {
      if (script.re.test(ch)) {
        scripts.add(script.name);
        break;
      }
    }
  }

  const scriptList = [...scripts];
  const mixed = scriptList.length > 1;
  const suspicious = mixed || hasNonAscii;

  const reason = mixed
    ? `mixed Unicode scripts (${scriptList.join(', ')}) — possible homoglyph attack`
    : hasNonAscii
      ? 'contains non-ASCII characters'
      : undefined;

  return { suspicious, scripts: scriptList, hasNonAscii, ...(reason ? { reason } : {}) };
}
