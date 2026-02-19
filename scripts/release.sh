#!/bin/bash
set -euo pipefail

# Helper script to trigger a unified release (Rust + Python)
# This script triggers the unified-release.yml GitHub Actions workflow

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Trigger a unified release of Rust crates and Python package in lockstep.

OPTIONS:
    -b, --bump TYPE         Version bump type: patch|minor|major (default: patch)
    -v, --version VERSION   Force a specific version (e.g., 0.1.2-beta.1)
    -s, --skip-tests        Skip running tests (use with caution)
    -d, --dry-run           Build everything but skip commits and publishing
    -h, --help              Show this help message

EXAMPLES:
    # Bump patch version (e.g., 0.1.2-beta.0 -> 0.1.2-beta.1)
    $0 --bump patch

    # Bump minor version
    $0 --bump minor

    # Force a specific version
    $0 --version 0.1.3-beta.0

    # Quick release without tests (use with caution)
    $0 --bump patch --skip-tests

    # Dry run to validate everything works
    $0 --bump patch --dry-run

NOTES:
    - This script requires 'gh' (GitHub CLI) to be installed and authenticated
    - The release will build and publish:
        * Rust protocol crate to crates.io
        * Rust CLI crate to crates.io
        * Python package to PyPI
        * GitHub Release with binaries
    - All artifacts are released with the same version number (converted to PEP 440 for Python)
EOF
    exit 0
}

BUMP_TYPE="patch"
FORCE_VERSION=""
SKIP_TESTS="false"
DRY_RUN="false"

while [[ $# -gt 0 ]]; do
    case $1 in
        -b|--bump)
            BUMP_TYPE="$2"
            shift 2
            ;;
        -v|--version)
            FORCE_VERSION="$2"
            shift 2
            ;;
        -s|--skip-tests)
            SKIP_TESTS="true"
            shift
            ;;
        -d|--dry-run)
            DRY_RUN="true"
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# Validate bump type
if [[ ! "$BUMP_TYPE" =~ ^(patch|minor|major)$ ]]; then
    echo "Error: Invalid bump type '$BUMP_TYPE'. Must be: patch, minor, or major"
    exit 1
fi

# Check if gh is installed
if ! command -v gh &> /dev/null; then
    echo "Error: GitHub CLI (gh) is not installed."
    echo "Install it from: https://cli.github.com/"
    exit 1
fi

# Check if authenticated
if ! gh auth status &> /dev/null; then
    echo "Error: Not authenticated with GitHub CLI."
    echo "Run: gh auth login"
    exit 1
fi

cd "$REPO_ROOT"

echo "=== Unified Release ==="
echo "Bump type: $BUMP_TYPE"
[[ -n "$FORCE_VERSION" ]] && echo "Force version: $FORCE_VERSION"
echo "Skip tests: $SKIP_TESTS"
echo "Dry run: $DRY_RUN"
echo ""

# Get current version
CURRENT_VERSION=$(grep '^version = ' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')
echo "Current version: $CURRENT_VERSION"

# Calculate new version if not forced
if [[ -n "$FORCE_VERSION" ]]; then
    NEW_VERSION="$FORCE_VERSION"
else
    NEW_VERSION=$(python3 scripts/version_tools.py bump --current "$CURRENT_VERSION" --kind "$BUMP_TYPE")
fi

PY_VERSION=$(python3 scripts/version_tools.py pep440 --version "$NEW_VERSION")

echo "New version: $NEW_VERSION"
echo "Python version: $PY_VERSION"
echo ""

if [[ "$DRY_RUN" == "true" ]]; then
    echo "⚠️  DRY RUN MODE - No commits or publishing will happen"
    echo ""
fi

read -p "Trigger release? [y/N] " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
fi

# Build workflow dispatch inputs
INPUTS="{\"bump_type\": \"$BUMP_TYPE\", \"skip_tests\": $SKIP_TESTS, \"dry_run\": $DRY_RUN"
if [[ -n "$FORCE_VERSION" ]]; then
    INPUTS="$INPUTS, \"force_version\": \"$FORCE_VERSION\""
fi
INPUTS="$INPUTS}"

echo "Triggering unified release workflow..."
gh workflow run unified-release.yml --json --raw-field inputs="$INPUTS"

echo ""
if [[ "$DRY_RUN" == "true" ]]; then
    echo "Dry run workflow triggered!"
    echo "This will build everything but skip commits and publishing."
else
    echo "Release workflow triggered!"
fi
echo "Monitor progress: gh run watch"
echo "Or visit: $(gh repo view --web --json url -q .url)/actions"
