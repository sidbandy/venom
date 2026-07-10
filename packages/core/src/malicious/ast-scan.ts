import { parse } from '@babel/parser';
import _traverse from '@babel/traverse';
import type { NodePath } from '@babel/traverse';

// @babel/traverse ships its callable as a CommonJS default export; under our
// module settings the namespace object needs unwrapping.
const traverse = ((_traverse as unknown as { default?: typeof _traverse }).default ??
  _traverse) as typeof _traverse;

export type AstSignalKind =
  | 'child-process' // spawning shells / commands
  | 'dynamic-eval' // eval / new Function
  | 'network' // http(s)/net/dns/fetch
  | 'env-access' // reading process.env (exfiltration of secrets)
  | 'filesystem' // fs writes to sensitive spots
  | 'obfuscation'; // dynamic require, buffer-from-base64, etc.

export interface AstSignal {
  kind: AstSignalKind;
  detail: string;
  line?: number;
}

const DANGEROUS_MODULES = new Set([
  'child_process',
  'node:child_process',
  'http',
  'https',
  'node:http',
  'node:https',
  'net',
  'node:net',
  'dgram',
  'dns',
  'node:dns',
  'tls',
  'vm',
  'node:vm',
]);

const NETWORK_MODULES = new Set(['http', 'https', 'net', 'dgram', 'dns', 'tls']);

/**
 * AST-based static analysis (SPEC.md §4 M3). Rather than grepping source (fragile,
 * easily evaded by formatting), we parse to an AST and ask precise structural
 * questions: does this code spawn processes, eval strings, open sockets, or read
 * environment variables? These are the fingerprints of a malicious payload.
 * Parsing never executes the code.
 */
export function scanSource(code: string): AstSignal[] {
  const signals: AstSignal[] = [];
  let ast;
  try {
    ast = parse(code, {
      sourceType: 'unambiguous',
      allowReturnOutsideFunction: true,
      errorRecovery: true,
      plugins: ['typescript', 'jsx'],
    });
  } catch {
    // A file we cannot parse yields no AST signals; entropy/pattern scans still apply.
    return signals;
  }

  const add = (kind: AstSignalKind, detail: string, line?: number): void => {
    signals.push({ kind, detail, ...(line !== undefined ? { line } : {}) });
  };

  traverse(ast, {
    CallExpression(path: NodePath) {
      const node = path.node as { callee?: unknown; arguments?: unknown[] };
      const callee = node.callee as Record<string, unknown> | undefined;
      const line = (path.node.loc?.start.line as number | undefined) ?? undefined;

      // require('child_process') / import of dangerous modules
      const required = requiredModuleName(callee, node.arguments);
      if (required && DANGEROUS_MODULES.has(required)) {
        add(
          NETWORK_MODULES.has(required.replace(/^node:/, '')) ? 'network' : 'child-process',
          `require('${required}')`,
          line,
        );
      }

      // eval(...) and new Function(...) handled below; here: direct eval call
      if (isIdentifier(callee, 'eval')) add('dynamic-eval', 'eval(...) call', line);

      // fetch(...) — network exfiltration in modern runtimes
      if (isIdentifier(callee, 'fetch')) add('network', 'fetch(...) call', line);

      // Buffer.from(x, 'base64') — classic payload decode
      if (isMemberCall(callee, 'Buffer', 'from') && hasBase64Arg(node.arguments)) {
        add('obfuscation', "Buffer.from(..., 'base64')", line);
      }
    },
    NewExpression(path: NodePath) {
      const node = path.node as { callee?: unknown };
      if (isIdentifier(node.callee as Record<string, unknown>, 'Function')) {
        add('dynamic-eval', 'new Function(...)', path.node.loc?.start.line);
      }
    },
    MemberExpression(path: NodePath) {
      // process.env access — where API keys and tokens live
      const node = path.node as {
        object?: Record<string, unknown>;
        property?: Record<string, unknown>;
      };
      if (
        node.object?.type === 'Identifier' &&
        node.object.name === 'process' &&
        node.property?.type === 'Identifier' &&
        node.property.name === 'env'
      ) {
        add('env-access', 'process.env access', path.node.loc?.start.line);
      }
    },
  });

  return signals;
}

function requiredModuleName(callee: unknown, args: unknown[] | undefined): string | undefined {
  if (!isIdentifier(callee as Record<string, unknown>, 'require')) return undefined;
  const first = args?.[0] as Record<string, unknown> | undefined;
  if (first?.type === 'StringLiteral' && typeof first.value === 'string') return first.value;
  return undefined;
}

function isIdentifier(node: Record<string, unknown> | undefined, name: string): boolean {
  return node?.type === 'Identifier' && node.name === name;
}

function isMemberCall(
  callee: Record<string, unknown> | undefined,
  object: string,
  property: string,
): boolean {
  if (callee?.type !== 'MemberExpression') return false;
  const obj = callee.object as Record<string, unknown> | undefined;
  const prop = callee.property as Record<string, unknown> | undefined;
  return isIdentifier(obj, object) && isIdentifier(prop, property);
}

function hasBase64Arg(args: unknown[] | undefined): boolean {
  return (args ?? []).some((a) => {
    const arg = a as Record<string, unknown>;
    return arg?.type === 'StringLiteral' && arg.value === 'base64';
  });
}
