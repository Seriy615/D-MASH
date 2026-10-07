'use strict';
// Executes the same real NaCl + bundled Kyber H1-H3 acceptance diagnostic
// used for release review; no mocked cryptographic success is accepted.
const {execFileSync}=require('node:child_process');
const path=require('node:path');
execFileSync(process.execPath,[path.resolve(__dirname,'../../../tools/diagnose_initial_handshake.cjs')],{stdio:'inherit'});
