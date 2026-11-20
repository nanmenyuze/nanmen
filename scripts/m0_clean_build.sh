#!/usr/bin/env bash
# M0 清洁构建入口。必须在没有 app/build、core/target、.gradle、.kotlin 的解压目录运行。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export JAVA_HOME="${JAVA_HOME:-/home/user/jdk17}"
export ANDROID_HOME="${ANDROID_HOME:-/home/user/Android/Sdk}"
export ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-$ANDROID_HOME}"
export PATH="$HOME/.cargo/bin:$JAVA_HOME/bin:$PATH"
LOG_DIR="${M0_LOG_DIR:-/tmp/namu-m0}"
mkdir -p "$LOG_DIR"

echo "M0 clean build: $ROOT"
echo "JAVA_HOME=$JAVA_HOME"
echo "ANDROID_HOME=$ANDROID_HOME"
java -version 2>&1 | head -3
rustc --version
cargo --version

python3 scripts/m0_validate.py | tee "$LOG_DIR/m0_validate.json"

echo "== cargo test =="
( cd core && cargo test ) 2>&1 | tee "$LOG_DIR/cargo-test.log"

echo "== gradle =="
./gradlew --no-daemon :app:testDebugUnitTest :app:lintDebug :app:verifyKernel :app:assembleDebug 2>&1 | tee "$LOG_DIR/gradle.log"

echo "== summaries =="
python3 - <<'PY' | tee "$LOG_DIR/summary.json"
import glob, json, os, re, xml.etree.ElementTree as ET
from pathlib import Path

app = Path('app')
tests = failures = errors = skipped = 0
suites = glob.glob(str(app / 'build/test-results/testDebugUnitTest/*.xml'))
for f in suites:
    r = ET.parse(f).getroot()
    tests += int(r.attrib.get('tests', 0))
    failures += int(r.attrib.get('failures', 0))
    errors += int(r.attrib.get('errors', 0))
    skipped += int(r.attrib.get('skipped', 0))
lint = ''
p = app / 'build/reports/lint-results-debug.txt'
if p.exists():
    lines = p.read_text(encoding='utf-8').splitlines()
    for line in reversed(lines):
        if re.search(r'\d+ errors?, \d+ warnings?', line):
            lint = line.strip(); break
apk = app / 'build/outputs/apk/debug/app-debug.apk'
import hashlib
sha = ''
if apk.exists():
    h = hashlib.sha256()
    with apk.open('rb') as f:
        for chunk in iter(lambda: f.read(8192), b''): h.update(chunk)
    sha = h.hexdigest()
print(json.dumps({
  'kotlin_suites': len(suites), 'kotlin_tests': tests, 'kotlin_failures': failures,
  'kotlin_errors': errors, 'kotlin_skipped': skipped, 'lint': lint,
  'apk_bytes': apk.stat().st_size if apk.exists() else None, 'apk_sha256': sha,
}, ensure_ascii=False, indent=2))
PY
