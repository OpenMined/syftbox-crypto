# syftbox-crypto-python (PyO3 bindings)

Python bindings for the `syftbox-crypto-protocol` crate, built with [PyO3](https://pyo3.rs/) and [maturin](https://www.maturin.rs/).

## Quick start

```bash
uv venv
uv pip install maturin
uv run -- maturin develop --manifest-path bindings/python/Cargo.toml

python - <<'PY'
import syftbox_crypto_python as sbc

material = sbc.generate_identity_material("alice@example.com")
print(material.fingerprint)
print(material.did)
print(material.recovery_key_hex)
PY
```

## Building wheels

```bash
uv venv
uv pip install maturin
uv run -- maturin build --release --manifest-path bindings/python/Cargo.toml
ls dist
```

## Development

- Format Rust code with `cargo fmt`
- Format Python stubs with `uv run ruff format python`
- Lint Python code with `uv run ruff check python`
