#!/usr/bin/env python3
"""Verify a local source candidate, not distribution or legal clearance."""
import argparse
import hashlib
import json
import re
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "contracts/source-candidate.json"
DIRECTORIES = ("crates", "tests", "scripts", "licenses", ".github")
FILES = ("Cargo.toml", "Cargo.lock", "README.md", ".gitignore", "contracts/extraction-source.json", "contracts/dependency-license-inventory.json")


def inventory():
    paths = [ROOT / name for name in FILES]
    for name in DIRECTORIES:
        paths.extend(path for path in (ROOT / name).rglob("*") if path.is_file() and "__pycache__" not in path.parts)
    return [{"path": str(path.relative_to(ROOT)), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            for path in sorted(paths)]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--write-candidate", action="store_true")
    args = parser.parse_args()
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--offline", "--locked", "--format-version", "1"], cwd=ROOT))
    expected = {"agent-core", "agent-runtime", "agent-storage", "agent-sandbox"}
    local = [package for package in metadata["packages"] if package["source"] is None]
    assert {package["name"] for package in local} == expected, "unexpected local package closure"
    assert all(Path(package["manifest_path"]).resolve().is_relative_to(ROOT) for package in local), "external local source"
    declared = json.loads((ROOT / "contracts/dependency-license-inventory.json").read_text())
    expected_dependencies = {(package["name"], package["version"], package["source"])
                             for package in declared["packages"]}
    actual_dependencies = {(package["name"], package["version"], package["source"])
                           for package in metadata["packages"] if package["source"] is not None}
    assert actual_dependencies == expected_dependencies, "dependency inventory drift; review the locked closure"
    files = inventory()
    for record in files:
        path = ROOT / record["path"]
        assert not path.is_symlink(), "symlink in source candidate"
        assert not (path.name == ".env" or (path.name.startswith(".env.") and path.name != ".env.example")), "environment file in candidate"
        assert path.suffix not in {".pem", ".key", ".p12", ".sqlitedb"}, "private artifact in candidate"
        if path.suffix in {".rs", ".json", ".py", ".sh", ".toml", ".txt", ".md", ".yml", ".yaml"}:
            raw = path.read_bytes()
            assert not re.search(br"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----\r?\n[A-Za-z0-9+/=]{32,}", raw), "private key material"
    if args.write_candidate:
        MANIFEST.write_text(json.dumps({"schema": "nazz.core-source-candidate.v1", "source_revision": None,
            "production_pin": False, "release_clearance": False,
            "scope": "local source and dependency boundary; not complete secret or license clearance",
            "files": files}, indent=2) + "\n")
    else:
        candidate = json.loads(MANIFEST.read_text())
        assert candidate["files"] == files, "candidate source drift; review before refreshing inventory"
    print(json.dumps({"source_boundary": "pass", "files": len(files), "packages": len(metadata["packages"]),
        "local_packages": sorted(expected), "production_pin": False, "release_clearance": False}))


if __name__ == "__main__":
    main()
