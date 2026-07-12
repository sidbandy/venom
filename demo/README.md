# Venom demo repos

Four curated scenarios, each isolating one capability (SPEC.md §13). Build Venom
first (`npm run build` at the repo root), then use `V="node packages/cli/dist/index.js"`.

### 1. Outdated dependencies with real CVEs — `outdated-cves/`

Pinned to `lodash@4.17.15` and `minimist@1.2.0`, both carrying documented CVEs.

```bash
$V audit demo/outdated-cves
```

Venom queries OSV live and reports the CVEs with remediation targets.

### 2. Typosquat in the manifest — `typosquat/`

Declares `expres` — one edit from the hugely popular `express`.

```bash
$V audit demo/typosquat      # flags it in the tree
$V check expres              # the Bouncer, before install
```

### 3. Unhealthy tree (unused dependencies) — `unhealthy/`

Declares three dependencies it never imports — dead weight and attack surface.

```bash
$V unused demo/unhealthy
```

### 4. Secret in git history — `planted-secrets/`

A secret committed and then "removed" in a later commit — still recoverable.

```bash
sh demo/planted-secrets/setup.sh   # builds a throwaway repo, prints its path
$V secrets <printed-path>          # Venom recovers the key from history
```

## Real-world validation

Venom also produces genuinely useful, non-contrived output on real projects — run
it against any real repo you have (or clone Express / a Flask project) to see it
work on real dependency trees:

```bash
$V audit /path/to/some/real/project
```
