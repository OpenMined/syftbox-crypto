# SbC CLI Tutorial – Managing Identity Bundles

This guide focuses on the `sbc key` commands. You will generate local identity
material, import a counterparty’s public bundle with TOFU protections, verify
bundles, and observe how the CLI reacts when fingerprints change.

All commands assume you are running from the repository root. Run `just init-sandbox`
first if you want a clean Alice/Bob playground; it creates the vault layouts,
datasite mirrors, and initial key material.

---

## 1. Generate Identity Material

Key generation writes private material into the vault (`.sbc/keys/`) and can
optionally export a public bundle into the datasite tree so other parties can
fetch it.

```bash
sbc \
  --vault sandbox/alice/.sbc \
  key generate \
  --identity alice@example.org \
  --overwrite \
  --bundle-out alice@example.org/public/crypto/did.json

sbc \
  --vault sandbox/bob/.sbc \
  key generate \
  --identity bob@example.org \
  --overwrite \
  --bundle-out bob@example.org/public/crypto/did.json
```

- `--overwrite` lets you rerun the command without manual cleanup.
- Bundles land under `sandbox/<user>/datasites/<identity>/public/crypto/did.json`.

Use `sbc key list --verbose` to view stored identities and bundle sizes:

```bash
sbc --vault sandbox/alice/.sbc key list --verbose
```

---

## 2. Import a Counterparty Bundle (TOFU)

Copy the other party’s bundle into your datasite tree, then register it in your
vault. This pins the first-seen fingerprint so `file inspect` and future imports
can detect tampering.

```bash
# Bob receives Alice’s bundle
mkdir -p sandbox/bob/datasites/alice@example.org/public/crypto
cp \
  sandbox/alice/datasites/alice@example.org/public/crypto/did.json \
  sandbox/bob/datasites/alice@example.org/public/crypto/did.json

sbc \
  --vault sandbox/bob/.sbc \
  key import \
  --bundle alice@example.org/public/crypto/did.json \
  --expected-identity alice@example.org
```

A successful import prints the bundle identity and fingerprint, then writes a
canonical copy to `sandbox/bob/.sbc/bundles/alice@example.org.json`. Repeat the
steps in reverse so Alice caches Bob’s bundle.

```
mkdir -p sandbox/alice/datasites/bob@example.org/public/crypto
cp \
  sandbox/bob/datasites/bob@example.org/public/crypto/did.json \
  sandbox/alice/datasites/bob@example.org/public/crypto/did.json

sbc \
  --vault sandbox/alice/.sbc \
  key import \
  --bundle bob@example.org/public/crypto/did.json \
  --expected-identity bob@example.org
```

### Verification Only

Add `--verify-only` to validate signatures without storing the
bundle:

```bash
sbc \
  --vault sandbox/bob/.sbc \
  key import \
  --bundle alice@example.org/public/crypto/did.json \
  --expected-identity alice@example.org \
  --verify-only
```

---

## 3. Inspect Cached Bundles

`sbc key verify` lets you examine bundle metadata without touching the vault:

```bash
sbc \
  --vault sandbox/bob/.sbc \
  key verify \
  --bundle alice@example.org/public/crypto/did.json \
  --expected-identity alice@example.org \
  --json
```

If the bundle body doesn’t contain the expected identity, the CLI prints a
warning. `--json` emits a minimal JSON blob (path + length) so scripts can parse
the output.

You can also re-run `key list --verbose` to confirm the cached fingerprint and
file size tracked on disk.

---

## 4. TOFU Warnings During `file inspect`

Once the counterparty bundle is cached, decrypting or inspecting their files
cross-checks the sender fingerprint. For example:

If you have already run through the file-encryption tutorial the ciphertext will
be present. Otherwise seed a demo message first:

```bash
cat > sandbox/alice/unencrypted/alice@example.org/shared/bob@example.org/files/message.txt <<'TEXT'
Hello from Alice via keys tutorial.
TEXT

sbc \
  --vault sandbox/alice/.sbc \
  file encrypt \
  --relative alice@example.org/shared/bob@example.org/files/message.txt \
  --recipient bob@example.org \
  --sender alice@example.org

cp \
  sandbox/alice/datasites/alice@example.org/shared/bob@example.org/files/message.txt \
  sandbox/bob/datasites/bob@example.org/shared/alice@example.org/files/message.txt
```

Now inspect the ciphertext:

```bash
sbc \
  --vault sandbox/bob/.sbc \
  file inspect \
  --input bob@example.org/shared/alice@example.org/files/message.txt \
  --identity bob@example.org \
  --verbose
```

Sample output:

```
  sender: alice@example.org (ik_fingerprint: 8d3eb7d3c4bb1f3d...c1f4a29b7f08a6d3)
  cached sender fingerprint matches (8d3eb7d3c4bb1f3d...c1f4a29b7f08a6d3)
```

If the cached fingerprint differs, `file inspect` prints:

```
  warning: cached sender fingerprint 8d3eb7d3c4bb1f3d...c1f4a29b7f08a6d3 differs from envelope 5a90d57e2c2ef8c4...9b8d0f1b3ac4e122 (TOFU violation)
```

Use this to catch unexpected rekeys or tampering before decrypting data.

---

## 5. Handling Fingerprint Changes

When the cached bundle exists and a new bundle claims the same identity with a
different fingerprint, `key import` blocks the operation unless you supply
`--force`.

```bash
# simulate a tampered bundle by swapping Bob's keys while claiming Alice's identity
cp \
  sandbox/bob/datasites/bob@example.org/public/crypto/did.json \
  sandbox/alice/datasites/alice@example.org/public/crypto/did-tampered.json
jq \
  '.identity = "alice@example.org" |
   .identity_fingerprint = "bob-pretending-to-be-alice" |
   .id = "did:web:syftbox.net:alice%40example.org"' \
  sandbox/alice/datasites/alice@example.org/public/crypto/did-tampered.json \
  > sandbox/alice/datasites/alice@example.org/public/crypto/did-tampered.json.tmp
mv \
  sandbox/alice/datasites/alice@example.org/public/crypto/did-tampered.json.tmp \
  sandbox/alice/datasites/alice@example.org/public/crypto/did-tampered.json

# deliver the tampered bundle to Bob's datasite (simulating sync)
cp \
  sandbox/alice/datasites/alice@example.org/public/crypto/did-tampered.json \
  sandbox/bob/datasites/alice@example.org/public/crypto/did-tampered.json

sbc \
  --vault sandbox/bob/.sbc \
  key import \
  --bundle alice@example.org/public/crypto/did-tampered.json \
  --expected-identity alice@example.org
```

This prints an error similar to:

```
sbc: bundle for alice@example.org already cached with fingerprint 8d3eb7d3c4bb1f3d...c1f4a29b7f08a6d3 – new fingerprint 5a90d57e2c2ef8c4...9b8d0f1b3ac4e122 requires --force
```

When you intentionally need to rotate keys, re-run the command with `--force`:

```bash
sbc \
  --vault sandbox/bob/.sbc \
  key import \
  --bundle alice@example.org/public/crypto/did-tampered.json \
  --expected-identity alice@example.org \
  --force
```

The CLI warns about the overwrite, updates the cached bundle, and future
`file inspect` calls will mention the fingerprint mismatch until senders start
using the new key.

---

## 6. Summary

1. Generate identities with `sbc key generate --identity … --bundle-out …`.
2. Exchange public bundles and import them with `sbc key import`, specifying
   `--expected-identity` to enforce TOFU.
3. Use `--verify-only` for dry runs, `--force` when intentionally replacing a
   cached bundle, and `key verify` / `key list` to probe metadata.
4. Let `file inspect` guard decrypt operations by comparing sender fingerprints
   against the cached bundle.
