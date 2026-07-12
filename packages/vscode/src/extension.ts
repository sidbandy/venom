import { basename } from 'node:path';
import { tmpdir } from 'node:os';
import * as vscode from 'vscode';
import {
  auditProject,
  checkCandidate,
  createScanContext,
  detectHomoglyphs,
  detectTyposquat,
  popularNamesFor,
  type AuditResult,
} from '@venom/core';

// The extension is a thin rendering layer over @venom/core (SPEC.md §7) — every
// detection is the engine's; this file only maps results onto VS Code UI.

let statusBar: vscode.StatusBarItem;
let output: vscode.OutputChannel;
let diagnostics: vscode.DiagnosticCollection;
/** Last full audit, reused to decorate package.json without re-hitting the network. */
let lastResult: AuditResult | undefined;

export function activate(context: vscode.ExtensionContext): void {
  statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusBar.command = 'venom.audit';
  statusBar.text = '$(shield) Venom';
  statusBar.tooltip = 'Venom supply-chain health — click to audit';
  statusBar.show();

  output = vscode.window.createOutputChannel('Venom');
  diagnostics = vscode.languages.createDiagnosticCollection('venom');

  context.subscriptions.push(
    statusBar,
    output,
    diagnostics,
    vscode.commands.registerCommand('venom.audit', () => {
      output.show(true);
      return runFullAudit();
    }),
    vscode.commands.registerCommand('venom.check', checkPackageCommand),
    vscode.workspace.onDidSaveTextDocument(lintManifest),
    vscode.workspace.onDidOpenTextDocument(lintManifest),
  );

  for (const doc of vscode.workspace.textDocuments) lintManifest(doc);
  void runFullAudit();
}

export function deactivate(): void {
  // subscriptions are disposed by VS Code.
}

function workspaceRoot(): string | undefined {
  return vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
}

function isOffline(): boolean {
  return vscode.workspace.getConfiguration('venom').get<boolean>('offline', false);
}

/** Run the full audit, update the status-bar score, output channel, and diagnostics. */
async function runFullAudit(): Promise<void> {
  const root = workspaceRoot();
  if (!root) {
    vscode.window.showWarningMessage('Venom: open a folder to audit.');
    return;
  }
  setStatus('$(sync~spin) Venom: auditing…');
  const ctx = createScanContext({ projectRoot: root, offline: isOffline() });
  try {
    const result = await auditProject(ctx);
    lastResult = result;
    const h = result.healthScore;
    setStatus(`$(shield) Venom ${h.score}/100 (${h.grade})`, statusColor(h.score));

    output.clear();
    output.appendLine(`Venom audit — ${result.graph.root.name}`);
    output.appendLine(`Health Score: ${h.score}/100 (grade ${h.grade})`);
    for (const c of h.components) output.appendLine(`  ${c.label}: ${c.score}/100 — ${c.summary}`);
    output.appendLine('');
    output.appendLine(
      `Vulnerabilities: ${result.vulnerabilities.length} · Package risk: ${result.assessments.length} · ` +
        `Secrets: ${result.secrets.length} · Unused deps: ${result.unusedDependencies.length}`,
    );

    for (const doc of vscode.workspace.textDocuments) lintManifest(doc);
  } catch (err) {
    setStatus('$(warning) Venom: audit failed');
    vscode.window.showErrorMessage(`Venom: ${err instanceof Error ? err.message : String(err)}`);
  } finally {
    ctx.dispose();
  }
}

/** The Bouncer, in-editor: decorate package.json dependency lines with risk. */
function lintManifest(document: vscode.TextDocument): void {
  if (basename(document.fileName) !== 'package.json') return;

  let pkg: { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
  try {
    pkg = JSON.parse(document.getText());
  } catch {
    diagnostics.set(document.uri, []);
    return;
  }

  const ranges = depLineRanges(document);
  const deps = Object.keys({ ...pkg.dependencies, ...pkg.devDependencies });
  const popular = popularNamesFor('npm');
  const diags: vscode.Diagnostic[] = [];

  for (const name of deps) {
    const range = ranges.get(name);
    if (!range) continue;

    const typo = detectTyposquat(name, popular);
    if (typo.suspicious) {
      diags.push(
        diag(
          range,
          `possible typosquat of "${typo.target}" (edit distance ${typo.distance}).`,
          vscode.DiagnosticSeverity.Error,
        ),
      );
    }
    const homo = detectHomoglyphs(name);
    if (homo.suspicious && homo.reason) {
      diags.push(diag(range, homo.reason, vscode.DiagnosticSeverity.Error));
    }

    if (lastResult) {
      const vulns = lastResult.vulnerabilities.filter((v) => v.affected.name === name);
      if (vulns.length > 0) {
        const ids = vulns
          .slice(0, 3)
          .map((v) => v.aliases.find((a) => a.startsWith('CVE')) ?? v.id);
        diags.push(
          diag(
            range,
            `${vulns.length} known vulnerability(ies): ${ids.join(', ')}.`,
            vscode.DiagnosticSeverity.Warning,
          ),
        );
      }
      if (lastResult.unusedDependencies.includes(name)) {
        diags.push(
          diag(
            range,
            'declared but never imported — unused dependency.',
            vscode.DiagnosticSeverity.Information,
          ),
        );
      }
    }
  }

  diagnostics.set(document.uri, diags);
}

/** Command-palette Bouncer check for a name before it's even in the manifest. */
async function checkPackageCommand(): Promise<void> {
  const name = await vscode.window.showInputBox({
    prompt: 'Package to vet before installing',
    placeHolder: 'e.g. express',
  });
  if (!name) return;

  const ctx = createScanContext({ projectRoot: workspaceRoot() ?? tmpdir(), offline: isOffline() });
  try {
    const a = await checkCandidate('npm', name.trim(), ctx, { deep: false });
    const detail = a.reasons.length
      ? a.reasons.map((r) => `• ${r}`).join('\n')
      : 'No risk signals detected.';
    const heading = `${a.ref.name}${a.ref.version ? `@${a.ref.version}` : ''}`;
    if (a.verdict === 'flagged') {
      vscode.window.showErrorMessage(`🚫 Flagged: ${heading}`, { modal: true, detail });
    } else if (a.verdict === 'caution') {
      vscode.window.showWarningMessage(`⚠️ Caution: ${heading}`, { modal: true, detail });
    } else {
      vscode.window.showInformationMessage(`✅ Clear: ${heading}`, { modal: true, detail });
    }
  } catch (err) {
    vscode.window.showErrorMessage(`Venom: ${err instanceof Error ? err.message : String(err)}`);
  } finally {
    ctx.dispose();
  }
}

/** Map each `"key": "value"` line in package.json to the range of its key. */
function depLineRanges(document: vscode.TextDocument): Map<string, vscode.Range> {
  const map = new Map<string, vscode.Range>();
  for (let line = 0; line < document.lineCount; line++) {
    const text = document.lineAt(line).text;
    const match = /^\s*"([^"]+)"\s*:\s*"/.exec(text);
    if (!match) continue;
    const name = match[1]!;
    const start = text.indexOf(`"${name}"`);
    map.set(name, new vscode.Range(line, start, line, start + name.length + 2));
  }
  return map;
}

function diag(
  range: vscode.Range,
  message: string,
  severity: vscode.DiagnosticSeverity,
): vscode.Diagnostic {
  const d = new vscode.Diagnostic(range, `Venom: ${message}`, severity);
  d.source = 'Venom';
  return d;
}

function setStatus(text: string, color?: vscode.ThemeColor): void {
  statusBar.text = text;
  statusBar.backgroundColor = color;
}

function statusColor(score: number): vscode.ThemeColor | undefined {
  if (score < 60) return new vscode.ThemeColor('statusBarItem.errorBackground');
  if (score < 80) return new vscode.ThemeColor('statusBarItem.warningBackground');
  return undefined;
}
