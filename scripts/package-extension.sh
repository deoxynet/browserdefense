#!/usr/bin/env bash
# Package a previously built extension. Usage: package-extension.sh [consumer|enterprise]
set -euo pipefail
cd "$(dirname "$0")/.."

case "${1:-consumer}" in
  consumer) BUILD_DIR=dist; PREFIX=browserdefense ;;
  enterprise) BUILD_DIR=dist-enterprise; PREFIX=browserdefense-enterprise ;;
  *) echo 'Usage: package-extension.sh [consumer|enterprise]' >&2; exit 1 ;;
esac

if [[ ! -f "$BUILD_DIR/manifest.json" ]]; then
  echo 'Missing build. Run pnpm run build:all first.' >&2
  exit 1
fi

# Reject unexpected artifacts before creating an archive, including key files.
node --input-type=module - "$BUILD_DIR" <<'JS'
import { readdirSync, statSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Script } from 'node:vm';
const root = process.argv[2];
const manifest = JSON.parse(readFileSync(join(root, 'manifest.json'), 'utf8'));
const version = JSON.parse(readFileSync('package.json', 'utf8')).version;
if (manifest.version !== version) throw new Error('Manifest/package version mismatch');
function check(dir) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) { check(path); continue; }
    if (name.startsWith('.') || !/\.(js|css|html|png)$/.test(name) && path !== join(root, 'manifest.json')) {
      throw new Error(`Unexpected release file: ${path}`);
    }
    const content = readFileSync(path, 'utf8');
    if (/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|["']d["']\s*:\s*["'][A-Za-z0-9_-]{32,}["']/.test(content)) {
      throw new Error(`Private key material in release: ${path}`);
    }
  }
}
check(root);
for (const script of manifest.content_scripts ?? []) {
  for (const file of script.js) new Script(readFileSync(join(root, file), 'utf8'));
}
JS

VERSION=$(node --input-type=module -e "import fs from 'node:fs'; console.log(JSON.parse(fs.readFileSync('$BUILD_DIR/manifest.json')).version)")
OUTPUT="$PREFIX-v$VERSION.zip"
rm -f "$OUTPUT"
(cd "$BUILD_DIR" && zip -qr "../$OUTPUT" .)
echo "Created $OUTPUT ($(du -h "$OUTPUT" | cut -f1 | xargs))"
