import {build} from 'esbuild';
import {copyFile, writeFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
const here = fileURLToPath(new URL('.', import.meta.url));
const out = fileURLToPath(new URL('../../D-MASH PWA/not_messenger/js/vendor/', import.meta.url));
await build({absWorkingDir:here, entryPoints:['blake3-entry.js'], outfile:out+'blake3.min.js',
    bundle:true, minify:true, format:'iife', globalName:'DmashBlake3', platform:'browser',
    target:['es2020'], legalComments:'inline',
    footer:{js:'if (typeof module !== "undefined") module.exports = DmashBlake3;'}});
await copyFile(here+'node_modules/@noble/hashes/LICENSE', out+'blake3.LICENSE.txt');
await writeFile(out+'blake3.PROVENANCE.txt',
    '@noble/hashes 2.4.0, BLAKE3 only. MIT license.\n' +
    'Source: https://github.com/paulmillr/noble-hashes/tree/2.4.0\n' +
    'Build: cd tools/vendor && npm ci --ignore-scripts && npm run build\n' +
    'Package integrity and esbuild 0.28.2 are pinned in package-lock.json.\n' +
    'Upstream independent 2022 audit excluded BLAKE3; do not claim independent audit coverage for this component.\n' +
    'This adapter is for Node identity work parity with backend BLAKE3, not new Account cryptography.\n');
