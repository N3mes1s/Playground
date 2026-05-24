'use strict';

// Stage 2 detonation script: require lodash inside the Unikraft Node
// unikernel, record events, emit a JSON verdict between markers so the
// host-side parser can extract it from the firecracker serial console.

const start = Date.now();
const events = [];
const errors = [];

function tick(type, extra) {
  events.push(Object.assign({ t: Date.now() - start, type }, extra || {}));
}

tick('boot');

let verdict = 'OK';

try {
  const lodash = require('lodash');
  tick('require_ok', { name: 'lodash', version: lodash.VERSION });
  const sample = lodash.chunk([1, 2, 3, 4, 5, 6], 2);
  tick('lodash_chunk', { sample });
} catch (e) {
  verdict = 'FAIL';
  errors.push({ phase: 'require', message: String(e && e.message || e) });
}

const result = {
  verdict,
  elapsed_ms: Date.now() - start,
  node_version: process.version,
  events,
  errors,
};

console.log('DETONATE_JSON_BEGIN');
console.log(JSON.stringify(result));
console.log('DETONATE_JSON_END');
