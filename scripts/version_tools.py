#!/usr/bin/env python3
"""Small helpers for version bumping and PEP 440 conversion."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


SEMVER_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$")


def parse_version(version: str):
    m = SEMVER_RE.match(version)
    if not m:
        raise SystemExit(f"Unable to parse version: {version}")
    major, minor, patch = map(int, m.groups()[:3])
    prerelease = m.group(4)
    return major, minor, patch, prerelease


def bump_pre(pre: str | None) -> str | None:
    if pre is None:
        return None
    parts = pre.split(".")
    if parts and parts[-1].isdigit():
        parts[-1] = str(int(parts[-1]) + 1)
    else:
        parts.append("1")
    return ".".join(parts)


def bump_version(current: str, kind: str) -> str:
    major, minor, patch, pre = parse_version(current)

    if kind == "major":
        major, minor, patch, pre = major + 1, 0, 0, None
    elif kind == "minor":
        minor, patch, pre = minor + 1, 0, None
    else:  # patch
        if pre:
            pre = bump_pre(pre)
        else:
            patch += 1

    if pre:
        return f"{major}.{minor}.{patch}-{pre}"
    return f"{major}.{minor}.{patch}"


def to_pep440(version: str) -> str:
    major, minor, patch, pre = parse_version(version)
    if not pre:
        return version

    parts = pre.split(".")
    tag = parts[0].lower()
    num = parts[1] if len(parts) > 1 and parts[1].isdigit() else "0"

    if tag in ("alpha", "a"):
        pep = f"a{num}"
    elif tag in ("beta", "b"):
        pep = f"b{num}"
    elif tag in ("rc",):
        pep = f"rc{num}"
    elif tag in ("dev",):
        pep = f".dev{num}"
    else:
        pep = f".post{pre}"

    return f"{major}.{minor}.{patch}{pep}"


def update_cargo_toml(file_path: Path, version: str) -> None:
    """Update version in Cargo.toml (workspace or package)."""
    content = file_path.read_text()

    # Update [workspace.package] version or [package] version
    content = re.sub(
        r'^version = ".*"',
        f'version = "{version}"',
        content,
        count=1,
        flags=re.MULTILINE
    )

    # Update workspace dependency version for syftbox-crypto-protocol
    content = re.sub(
        r'syftbox-crypto-protocol = \{ path = "protocol", version = ".*" \}',
        f'syftbox-crypto-protocol = {{ path = "protocol", version = "{version}" }}',
        content
    )

    file_path.write_text(content)


def update_pyproject_toml(file_path: Path, version: str) -> None:
    """Update version in pyproject.toml."""
    content = file_path.read_text()

    content = re.sub(
        r'^version = ".*"',
        f'version = "{version}"',
        content,
        count=1,
        flags=re.MULTILINE
    )

    file_path.write_text(content)


def update_files(version: str, py_version: str | None = None) -> None:
    """Update all version files in the project."""
    repo_root = Path(__file__).parent.parent

    # Update root Cargo.toml (workspace)
    cargo_toml = repo_root / "Cargo.toml"
    if cargo_toml.exists():
        print(f"Updating {cargo_toml.relative_to(repo_root)}: {version}")
        update_cargo_toml(cargo_toml, version)

    # Update Python pyproject.toml
    pyproject = repo_root / "bindings" / "python" / "pyproject.toml"
    if pyproject.exists() and py_version:
        print(f"Updating {pyproject.relative_to(repo_root)}: {py_version}")
        update_pyproject_toml(pyproject, py_version)


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)

    bump = sub.add_parser("bump", help="Bump a semver version")
    bump.add_argument("--current", required=True)
    bump.add_argument(
        "--kind",
        choices=["major", "minor", "patch"],
        default="patch",
        help="How to bump the version",
    )

    pep = sub.add_parser("pep440", help="Convert semver to PEP440")
    pep.add_argument("--version", required=True)

    update = sub.add_parser("update", help="Update version files in the project")
    update.add_argument("--version", required=True, help="Semver version to set")

    args = parser.parse_args()

    if args.cmd == "bump":
        print(bump_version(args.current, args.kind))
    elif args.cmd == "pep440":
        print(to_pep440(args.version))
    elif args.cmd == "update":
        version = args.version
        py_version = to_pep440(version)
        update_files(version, py_version)
        print(f"✓ Updated to {version} (Python: {py_version})")
    else:
        raise SystemExit("Unknown command")


if __name__ == "__main__":
    main()
