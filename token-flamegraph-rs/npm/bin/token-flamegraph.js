#!/usr/bin/env node
const { execFileSync } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');

const BINARY_NAME = 'token-flamegraph';

function findBinary() {
  // Check local bin first
  const localBin = path.join(os.homedir(), '.local', 'bin', BINARY_NAME);
  if (fs.existsSync(localBin)) return localBin;

  // Check PATH
  const { execSync } = require('child_process');
  try {
    const which = execSync(`which ${BINARY_NAME} 2>/dev/null`).toString().trim();
    if (which) return which;
  } catch {}

  // Check npm package dir
  const pkgBin = path.join(__dirname, '..', 'binary', BINARY_NAME);
  if (fs.existsSync(pkgBin)) return pkgBin;

  return null;
}

const binary = findBinary();
if (!binary) {
  console.error('token-flamegraph binary not found.');
  console.error('Install: bash <(curl -sL https://raw.githubusercontent.com/N3mes1s/Playground/main/token-flamegraph-rs/install.sh)');
  console.error('Or build from source: cd token-flamegraph-rs && cargo build --release');
  process.exit(1);
}

try {
  execFileSync(binary, process.argv.slice(2), { stdio: 'inherit' });
} catch (e) {
  process.exit(e.status || 1);
}
