'use strict';
global.DmashBlake3 = require('../js/vendor/blake3.min.js');
const api = require('../js/node_identity.js');
const inputs = JSON.parse(require('node:fs').readFileSync(0, 'utf8'));
process.stdout.write(JSON.stringify(inputs.map(nodeId => ({hash: api.hash(nodeId), valid: api.verify(nodeId)}))));
