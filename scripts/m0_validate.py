#!/usr/bin/env python3
"""M0 静态校验：版本、kernel_version.txt、fixtures、cases、coverage、matrix 的引用完整性。

不运行 Gradle/Cargo；构建与测试结果由 M0 报告记录。可在清洁解压目录直接执行。
"""
from __future__ import annotations
import hashlib, json, re, sys
from pathlib import Path
from collections import Counter

ROOT = Path(__file__).resolve().parents[1]
errors: list[str] = []

def fail(msg: str):
    errors.append(msg)

def read_json(path: str):
    return json.loads((ROOT / path).read_text(encoding="utf-8"))

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def tree_digest(paths: list[Path]) -> str:
    h = hashlib.sha256()
    files = []
    for base in paths:
        if base.is_file():
            files.append(base)
        elif base.is_dir():
            files.extend(p for p in base.rglob("*") if p.is_file())
    for p in sorted(files):
        rel = p.relative_to(ROOT).as_posix()
        h.update(rel.encode() + b"\0")
        h.update(sha256_file(p).encode() + b"\0")
    return h.hexdigest()

# 1) versionName / versionCode
gradle = (ROOT / "app/build.gradle.kts").read_text(encoding="utf-8")
vm = re.search(r'versionName\s*=\s*"([^"]+)"', gradle)
vc = re.search(r'versionCode\s*=\s*(\d+)', gradle)
if not vm: fail("versionName not found")
if not vc: fail("versionCode not found")
version_name = vm.group(1) if vm else None
version_code = vc.group(1) if vc else None
if version_name != "2.3.12": fail(f"versionName={version_name}, expected 2.3.12")

# 2) kernel source version + kernel_version.txt
lib = (ROOT / "core/src/lib.rs").read_text(encoding="utf-8")
km = re.search(r'to_jstring\(&mut env,\s*"([0-9]+\.[0-9]+\.[0-9]+)"', lib)
if not km: fail("kernel version not found in core/src/lib.rs")
kernel_version = km.group(1) if km else None
stamp = (ROOT / "app/src/main/jniLibs/kernel_version.txt").read_text(encoding="utf-8").strip().splitlines()
if len(stamp) < 5: fail(f"kernel_version.txt has {len(stamp)} lines, expected >=5")
stamp_version = stamp[0] if stamp else None
if stamp_version != kernel_version: fail(f"kernel_version.txt={stamp_version}, lib.rs={kernel_version}")

# 3) kernel source hash
src_digest = hashlib.sha256()
for p in sorted((ROOT / "core/src").rglob("*.rs")):
    src_digest.update(p.read_bytes())
src_hash = src_digest.hexdigest()
if len(stamp) >= 2 and stamp[1] != src_hash:
    fail("kernel_version.txt source hash mismatch")

# 4) cargo hash
cargo_digest = hashlib.sha256()
for name in [".cargo/config.toml", "Cargo.lock", "Cargo.toml"]:
    p = ROOT / "core" / name
    if p.is_file():
        cargo_digest.update((p.relative_to(ROOT / "core").as_posix() + "\n").encode())
        cargo_digest.update(p.read_bytes())
cargo_hash = cargo_digest.hexdigest()
if len(stamp) >= 3 and stamp[2] != cargo_hash:
    fail("kernel_version.txt cargo hash mismatch")

# 5) .so hashes
for idx, abi in enumerate(["arm64-v8a", "armeabi-v7a"]):
    so = ROOT / "app/src/main/jniLibs" / abi / "libnanmen_core.so"
    if not so.exists():
        fail(f"missing {so}")
    elif len(stamp) >= 4 + idx and sha256_file(so) != stamp[3 + idx]:
        fail(f"{abi} .so hash mismatch")

# 6) fixtures / cases / coverage / matrix
fixtures = [p for p in (ROOT / "compat/fixtures").rglob("*") if p.is_file()]
if len(fixtures) != 48: fail(f"fixtures={len(fixtures)}, expected 48")
cases = read_json("compat/expected/cases.json")["cases"]
if len(cases) != 52: fail(f"cases={len(cases)}, expected 52")
ids = [c["id"] for c in cases]
if len(set(ids)) != len(ids): fail("duplicate case IDs")
case_fixtures = {c["fixture"] for c in cases if c["fixture"] != "n/a"}
for rel in case_fixtures:
    if not (ROOT / "compat/fixtures" / rel).is_file():
        fail(f"missing case fixture: {rel}")

coverage = read_json("compat/expected/coverage.json")
cov_ids = [c["case_id"] for c in coverage["cases"]]
if set(cov_ids) != set(ids): fail("coverage case IDs do not match cases.json")
if coverage["summary"]["total"] != len(cases): fail("coverage total mismatch")

matrix = read_json("compat/matrix.json")
row_ids = [r["id"] for r in matrix["rows"]]
if len(set(row_ids)) != len(row_ids): fail("duplicate matrix row IDs")
for r in matrix["rows"]:
    for cid in r["fixtures"]:
        if cid not in set(ids): fail(f"matrix {r['id']} references unknown case {cid}")

# 7) targets / source digest
targets = read_json("compat/targets.json")
if not targets.get("loon", {}).get("target_version"): fail("loon target_version missing")
if not targets.get("shadowrocket", {}).get("target_version"): fail("shadowrocket target_version missing")
digest_paths = [
    ROOT / "app/build.gradle.kts", ROOT / "build.gradle.kts", ROOT / "settings.gradle.kts", ROOT / "gradle",
    ROOT / "app/src", ROOT / "core/src", ROOT / "core/tests",
    ROOT / "core/Cargo.toml", ROOT / "core/Cargo.lock", ROOT / "core/build-android.sh",
    ROOT / "compat/fixtures", ROOT / "compat/expected/cases.json",
]
code_digest = tree_digest(digest_paths)

summary = {
    "versionName": version_name,
    "versionCode": int(version_code) if version_code else None,
    "kernel_version": kernel_version,
    "kernel_source_hash": src_hash,
    "kernel_cargo_hash": cargo_hash,
    "fixtures": len(fixtures),
    "cases": len(cases),
    "coverage": coverage["summary"],
    "matrix_rows": len(matrix["rows"]),
    "matrix_status": dict(Counter(r["status"] for r in matrix["rows"])),
    "code_source_sha256": code_digest,
    "errors": errors,
}
print(json.dumps(summary, ensure_ascii=False, indent=2))
if errors:
    sys.exit(1)
