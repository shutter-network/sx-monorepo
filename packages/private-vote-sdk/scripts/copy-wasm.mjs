// Cross-platform replacement for `cp src/crypto/blst/blst.wasm dist/blst.wasm`.
import { copyFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const src = join(root, 'src', 'crypto', 'blst', 'blst.wasm');
const dst = join(root, 'dist', 'blst.wasm');

mkdirSync(dirname(dst), { recursive: true });
copyFileSync(src, dst);
console.log(`copied ${src} -> ${dst}`);
