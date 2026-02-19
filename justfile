# syftbox-crypto justfile
# Minimal essential commands for development

_default:
    @just --list

# Build entire workspace
# Install recommended development tools
install-dev-tools:
    -cargo install cargo-watch
    -cargo install cargo-audit
    -cargo install cargo-outdated
    -cargo install cargo-machete
    -cargo install cargo-tarpaulin

# Build the project in debug mode
build:
    cargo build --workspace

# Build only protocol library
build-protocol:
    cargo build -p syftbox-crypto-protocol

# Build only CLI
build-cli:
    cargo build -p syftbox-crypto-cli

# Build release version
build-release:
    cargo build --workspace --release

# Run all tests (24 tests)
test:
    cargo test --workspace

# Run protocol tests only
test-protocol:
    cargo test -p syftbox-crypto-protocol

# Run CLI tests only
test-cli:
    cargo test -p syftbox-crypto-cli

# Run CLI integration tests
test-integration-cli *ARGS:
    cargo build -p syftbox-crypto-cli
    cargo test -p syftbox-crypto-cli --test integration_test {{ARGS}}

# Run with verbose output
test-verbose:
    cargo test --workspace -- --nocapture

# Run full CLI check (lint-fix, test-cli, test-integration-cli)
check-cli:
    just lint-fix
    just test-cli
    just test-integration-cli

# Run full protocol check (lint-fix, test-protocol)
check-protocol:
    just lint-fix
    just test-protocol

# Run full workspace check (CLI + protocol)
check-all:
    just check-cli
    just check-protocol

# Run coverage on CLI workspace
coverage-cli *ARGS:
    ./coverage.sh --cli {{ARGS}}

# Run coverage on protocol workspace
coverage-protocol *ARGS:
    ./coverage.sh --protocol {{ARGS}}

# Run coverage on both workspaces
coverage-all *ARGS:
    ./coverage.sh --cli {{ARGS}}
    ./coverage.sh --protocol {{ARGS}}

# Format code
format:
    cargo fmt --all

# Check formatting without making changes
format-check:
    cargo fmt --all -- --check

# Run clippy linter
lint:
    cargo clippy --workspace --all-targets

# Run clippy with automatic fixes
lint-fix:
    cargo clippy --workspace --all-targets --fix --allow-dirty --allow-staged
    cargo fmt --all

# Run all pre-commit checks (format, lint, test)
pre-commit: format lint test

# Clean build artifacts
clean:
    cargo clean

# Generate documentation
doc:
    cargo doc --workspace --no-deps --open

# Run the CLI tool
run *ARGS:
    cargo run -p syftbox-crypto-cli -- {{ARGS}}

# Show help for CLI commands
cli-help:
    cargo run -p syftbox-crypto-cli -- --help

# Show help for keygen command
keygen-help:
    cargo run -p syftbox-crypto-cli -- keygen --help

# Show project structure
tree:
    tree -L 3 -I target

# Show dependency tree
deps:
    cargo tree

# Initialize sandbox directories, configs, and demo key material
init-sandbox:
    #!/usr/bin/env bash
    set -euo pipefail

    for user in alice bob; do
    identity="${user}@example.org"
    if [ "${user}" = "alice" ]; then
    other="bob"
    else
    other="alice"
    fi
    other_identity="${other}@example.org"
    base="sandbox/${user}"

    echo "Preparing sandbox for ${identity} (counterpart ${other_identity})"

    mkdir -p \
    "${base}/.sbc/config" \
    "${base}/.sbc/keys" \
    "${base}/.sbc/bundles" \
    "${base}/datasites/${identity}/public/crypto" \
    "${base}/datasites/${identity}/shared/${other_identity}/files" \
    "${base}/unencrypted/${identity}/public/crypto" \
    "${base}/unencrypted/${identity}/shared/${other_identity}/files"

    config_path="${base}/.sbc/config/datasite.json"
    printf '{\n  "encrypted_root": "../datasites",\n  "shadow_root": "../unencrypted"\n}\n' > "${config_path}"

    echo "Generating key material for ${identity}"
    ./sbc \
    --vault "${base}/.sbc" \
    key generate \
    --identity "${identity}" \
    --overwrite \
    --bundle-out "${identity}/public/crypto/did.json"
    done
