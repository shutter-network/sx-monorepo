#!/usr/bin/env node
/**
 * Refresh `tests/vectors-geg/` from the geg repo's canonical vector set.
 *
 * The vectors are checked in rather than read from a sibling checkout so the
 * parity gate is hermetic: CI must be able to run it without geg present. This
 * script is how the copy gets refreshed, and it rewrites PROVENANCE.md with the
 * geg commit it copied from so the snapshot is always attributable.
 *
 *   node scripts/sync-geg-vectors.mjs [path-to-geg-repo]
 *
 * Default path is the sibling layout used in development; override with the
 * argument or GEG_REPO.
 */
import { execFileSync } from 'node:child_process';
import {
  cpSync,
  existsSync,
  mkdirSync,
  readdirSync,
  rmSync,
  writeFileSync
} from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const DEST = resolve(HERE, '..', 'tests', 'vectors-geg');

const DEFAULT_GEG = resolve(
  HERE,
  '../../../../Munich_Voting/generalised-el-gamal'
);
const gegRepo = resolve(process.argv[2] || process.env.GEG_REPO || DEFAULT_GEG);
const src = join(gegRepo, 'tests', 'vectors');

if (!existsSync(src)) {
  console.error(
    `sync-geg-vectors: no vectors at ${src}\n` +
      `Pass the geg repo path: node scripts/sync-geg-vectors.mjs /path/to/generalised-el-gamal`
  );
  process.exit(1);
}

let commit = 'unknown';
let describe = '';
try {
  commit = execFileSync('git', ['-C', gegRepo, 'rev-parse', 'HEAD'], {
    encoding: 'utf8'
  }).trim();
  describe = execFileSync(
    'git',
    ['-C', gegRepo, 'log', '-1', '--format=%cI %s'],
    { encoding: 'utf8' }
  ).trim();
} catch {
  console.warn(
    'sync-geg-vectors: geg repo is not a git checkout; commit unknown'
  );
}

// Replace wholesale — a vector deleted upstream must disappear here too, or the
// gate silently keeps verifying a file geg no longer publishes.
rmSync(DEST, { recursive: true, force: true });
mkdirSync(DEST, { recursive: true });
cpSync(src, DEST, {
  recursive: true,
  filter: s => {
    const name = basename(s);
    if (name.startsWith('.')) return false; // .DS_Store and friends
    if (name.endsWith('.ts')) return false; // schema types stay ours
    // geg's own README describes the same categories PROVENANCE.md does. An
    // un-maintained copy of another repo's doc only rots — skip it.
    return name !== 'README.md';
  }
});

const categories = readdirSync(DEST, { withFileTypes: true })
  .filter(d => d.isDirectory())
  .map(d => ({
    name: d.name,
    count: readdirSync(join(DEST, d.name)).filter(f => f.endsWith('.json'))
      .length
  }))
  .sort((a, b) => a.name.localeCompare(b.name));

const total = categories.reduce((n, c) => n + c.count, 0);

writeFileSync(
  join(DEST, 'PROVENANCE.md'),
  `# geg conformance vectors — vendored copy

**Do not hand-edit.** Regenerate with:

\`\`\`bash
node scripts/sync-geg-vectors.mjs [path-to-geg-repo]
\`\`\`

| | |
|---|---|
| Source repo | \`generalised-el-gamal\` |
| Source path | \`tests/vectors/\` |
| Commit | \`${commit}\` |
| Commit date / subject | ${describe || 'n/a'} |
| Vectors | ${total} across ${categories.length} categories |

${categories.map(c => `- \`${c.name}/\` — ${c.count}`).join('\n')}

## Why these are checked in

\`tests/geg-parity.test.ts\` is a **blocking gate**: it proves this vendored fork
of the SDK has not diverged from what geg's Python implementation verifies. A
gate that skips when a sibling checkout is missing is not a gate, so the vectors
live here and CI runs them unconditionally.

## Why 13 of them duplicate \`tests/vectors/\` byte-for-byte

Deliberately, and the duplication is load-bearing — do not "deduplicate" it.

\`scripts/gen-vectors.ts\` writes to \`tests/vectors/\` (\`npm run gen-vectors\`). If
the parity gate read the shared vectors from there, then regenerating them would
silently repoint the gate at freshly-produced *local* bytes: it would keep
passing while no longer testing geg's corpus at all. This directory is the
pinned, geg-owned copy, and the only thing that may rewrite it is
\`sync-geg-vectors.mjs\`.

Two of the shared 15 (\`decrypt-share/share_basic.json\`,
\`tally/tally_basic.json\`) differ from our copies in their \`dleq_proof\` bytes
only — DLEQ proofs are randomized, so each repo generated a valid proof of an
identical statement with a different nonce. Cross-verifying both is exactly what
the gate checks.

Every file here is asserted: \`geg-parity.test.ts\` fails if any vector on disk
went unchecked, so there is no dead weight by construction.
`
);

console.log(
  `sync-geg-vectors: copied ${total} vectors (${categories.length} categories) from ${commit.slice(0, 12)}`
);
