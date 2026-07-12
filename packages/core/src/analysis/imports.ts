import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { parse } from '@babel/parser';
import _traverse from '@babel/traverse';
import { listProjectFiles, withExtensions } from '../util/files';

const traverse = ((_traverse as unknown as { default?: typeof _traverse }).default ??
  _traverse) as typeof _traverse;

const SOURCE_EXTENSIONS = new Set(['.js', '.cjs', '.mjs', '.jsx', '.ts', '.tsx', '.mts', '.cts']);

/**
 * Collect the set of package names a project's own source imports. Shared by the
 * unused-dependency detector and reachability analysis.
 */
export async function collectImportedPackages(projectRoot: string): Promise<Set<string>> {
  const files = withExtensions(await listProjectFiles(projectRoot), SOURCE_EXTENSIONS);
  const used = new Set<string>();
  for (const rel of files) {
    let code: string;
    try {
      code = await readFile(join(projectRoot, rel), 'utf8');
    } catch {
      continue;
    }
    for (const specifier of extractImports(code)) {
      const name = packageNameOf(specifier);
      if (name) used.add(name);
    }
  }
  return used;
}

/**
 * Extract the module specifiers a JS/TS source file imports — via `import`,
 * `export … from`, `require(...)`, and dynamic `import(...)`. Parsing only; never
 * executes. Used by the unused-dependency detector.
 */
export function extractImports(code: string): string[] {
  const specifiers = new Set<string>();
  let ast;
  try {
    ast = parse(code, {
      sourceType: 'unambiguous',
      errorRecovery: true,
      plugins: ['typescript', 'jsx'],
    });
  } catch {
    return [];
  }

  const addString = (node: unknown): void => {
    const n = node as { type?: string; value?: unknown };
    if (n?.type === 'StringLiteral' && typeof n.value === 'string') specifiers.add(n.value);
  };

  traverse(ast, {
    ImportDeclaration(path) {
      specifiers.add(path.node.source.value);
    },
    ExportNamedDeclaration(path) {
      if (path.node.source) specifiers.add(path.node.source.value);
    },
    ExportAllDeclaration(path) {
      specifiers.add(path.node.source.value);
    },
    CallExpression(path) {
      const callee = path.node.callee as { type?: string; name?: string };
      if ((callee.type === 'Identifier' && callee.name === 'require') || callee.type === 'Import') {
        addString(path.node.arguments[0]);
      }
    },
  });

  return [...specifiers];
}

/**
 * Resolve a module specifier to its package name. Relative/absolute paths and
 * Node builtins return null. Scoped packages keep their `@scope/name`.
 */
export function packageNameOf(specifier: string): string | null {
  if (!specifier || specifier.startsWith('.') || specifier.startsWith('/')) return null;
  if (specifier.startsWith('node:')) return null;
  const parts = specifier.split('/');
  if (specifier.startsWith('@')) {
    return parts.length >= 2 ? `${parts[0]}/${parts[1]}` : null;
  }
  return parts[0] ?? null;
}
