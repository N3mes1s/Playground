#!/usr/bin/env node
const { execSync } = require('child_process');
const os = require('os');
const fs = require('fs');
const path = require('path');
const https = require('https');

const REPO = 'N3mes1s/Playground';
const BINARY_NAME = 'token-flamegraph';

function getPlatformName() {
  const arch = os.arch() === 'arm64' ? 'aarch64' : 'x86_64';
  const platform = os.platform() === 'darwin' ? 'darwin' : 'linux';
  return `${platform}-${arch}`;
}

function downloadBinary() {
  const platformName = getPlatformName();
  const binaryDir = path.join(__dirname, '..', 'binary');
  const binaryPath = path.join(binaryDir, BINARY_NAME);

  // Skip if already exists
  if (fs.existsSync(binaryPath)) return;

  // Try to find latest release
  const url = `https://api.github.com/repos/${REPO}/releases/latest`;
  console.log(`  Downloading ${BINARY_NAME} for ${platformName}...`);

  try {
    const releaseJson = execSync(`curl -sL "${url}"`, { encoding: 'utf8' });
    const release = JSON.parse(releaseJson);
    const asset = release.assets?.find(a => a.name.includes(platformName));
    if (asset) {
      fs.mkdirSync(binaryDir, { recursive: true });
      execSync(`curl -sL "${asset.browser_download_url}" -o "${binaryPath}"`);
      fs.chmodSync(binaryPath, 0o755);
      console.log(`  ✓ Downloaded ${BINARY_NAME} ${release.tag_name}`);
      return;
    }
  } catch {}

  console.log('  ⚠ No pre-built binary found for your platform.');
  console.log('  Build from source: cd token-flamegraph-rs && cargo build --release');
}

downloadBinary();
