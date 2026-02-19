# syftbox-crypto

End-to-end encrypted communication and file synchronization for SyftBox using X3DH key agreement.

## Overview

This crate provides cryptographic primitives for secure messaging and file synchronization in SyftBox using Ed25519 identity signing, X25519 key agreement, and XChaCha20-Poly1305 for payload encryption.

## Status

This software is considered Beta so use at your own risk.

## Project Structure

Following the workspace pattern:

```
syftbox-crypto/
├── protocol/           # Core crypto library (keep as small as possible for easy security audit)
│   ├── src/
│   │   └── lib.rs
│   └── tests/          # Comprehensive tests
│
├── cli/                # Command-line interface to use the API in protocol/
│   └── src/
│       └── main.rs
│
└── Cargo.toml          # Workspace configuration
```

## Development

### Quick Start

```bash
just --list           # Show all commands
just build            # Build workspace
just test             # Run all tests
```

### Build Commands

```bash
just build            # Build entire workspace
just build-protocol   # Build only protocol library
just build-cli        # Build only CLI
just build-release    # Release build
```

### Test Commands

```bash
just test             # Run all tests
just test-protocol    # Protocol tests only
just test-verbose     # Tests with output
```

### Code Quality

```bash
just format           # Format code
just lint             # Run clippy
just pre-commit       # Format + lint + test
```

### CLI Commands

```bash
just run <ARGS>       # Run CLI with arguments
just cli-help         # Show CLI help
just keygen-help      # Show keygen help
```

### Utilities

```bash
just clean            # Clean build artifacts
just doc              # Generate documentation
just tree             # Show project structure
```

## License

Apache-2.0

## Repository

https://github.com/OpenMined/syftbox-crypto
