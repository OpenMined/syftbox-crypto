# SbC CLI Tutorial – Relative / Shadow Workflow

This companion tutorial walks through the **relative path** interface. Instead of spelling out datasite and shadow locations, you provide identity-relative paths (e.g. `alice@example.org/shared/...`) and the CLI consults the vault’s `config/datasite.json` to find the correct encrypted and plaintext roots.

Starting point:

- `sandbox/alice/.sbc` and `sandbox/bob/.sbc` already contain `config/datasite.json`.
- The directory structure matches the setup from `docs/cli/tutorial.md`.
- `sbc` is available from the workspace root.

We will encrypt a plaintext file for Bob and decrypt it again, relying solely on `--relative` lookups so the CLI drives all filesystem resolution.

---

## 0. Prepare Plaintext (if needed)

```bash
cat > sandbox/alice/unencrypted/alice@example.org/shared/bob@example.org/files/plain.txt <<'TEXT'
Bob,

Here’s a plaintext note sent via the shadow-aware relative API.

– Alice
TEXT
```

Confirm the plaintext exists only in the shadow tree (nothing under datasites yet):

```bash
find sandbox/alice -name 'plain.txt' | sort
# Expect to see only the shadow path here
echo "Shadow contents:"
cat sandbox/alice/unencrypted/alice@example.org/shared/bob@example.org/files/plain.txt
```

## 1. Generate Identities (same vault layout as the main tutorial)

### Alice

```bash
sbc \
  --vault sandbox/alice/.sbc \
  key generate \
  --identity alice@example.org \
  --overwrite \
  --bundle-out alice.example.org/bundles/alice.json
```

### Bob

```bash
sbc \
  --vault sandbox/bob/.sbc \
  key generate \
  --identity bob@example.org \
  --overwrite \
  --bundle-out bob.example.org/bundles/bob.json
```

> **Note:** `bundle-out` accepts any path. Because we stay in relative mode, using `alice@example.org/public/crypto/did.json` mirrors the datasite structure automatically.

## 2. Encrypt Using `--relative`

Hand the CLI the identity-scoped path you want to protect. It will read the plaintext from the shadow tree and emit ciphertext into the datasite tree.

```bash
sbc \
  --vault sandbox/alice/.sbc \
  file encrypt \
  --relative alice@example.org/shared/bob@example.org/files/plain.txt \
  --recipient bob@example.org
```

- No `--sender` flag is required; the CLI auto-detects the single identity in Alice’s vault.
- The plaintext is read from `sandbox/alice/unencrypted/...`, and a ciphertext with the same relative path (and filename) appears under `sandbox/alice/datasites/...`.

Verify the ciphertext now exists in the datasite tree (original shadow file is still present):

```bash
find sandbox/alice -name 'plain.txt' | sort
# You should now see both the shadow and datasite copies
echo "Datasite contents:"
cat sandbox/alice/datasites/alice@example.org/shared/bob@example.org/files/plain.txt
```

## 3. Deliver Ciphertext

```bash
cp \
  sandbox/alice/datasites/alice@example.org/shared/bob@example.org/files/plain.txt \
  sandbox/bob/datasites/bob@example.org/shared/alice@example.org/files/plain.txt
```

Before decryption, Bob only has the ciphertext copy:

```bash
find sandbox/bob -name 'plain.txt' | sort
# Expect to see only the datasite path at this point
```

## 4. Inspect Ciphertext (optional)

```bash
sbc \
  --vault sandbox/bob/.sbc \
  file inspect \
  --input bob@example.org/shared/alice@example.org/files/plain.txt \
  --identity bob@example.org \
  --verbose
```

Because the path is relative, the CLI expands it against Bob’s datasite root automatically.

## 5. Decrypt Using `--relative`

```bash
sbc \
  --vault sandbox/bob/.sbc \
  file decrypt \
  --relative bob@example.org/shared/alice@example.org/files/plain.txt \
  --identity bob@example.org
```

- Omit `--identity` if Bob’s vault only tracks one identity.
- The CLI reads ciphertext from Bob’s datasite tree and writes plaintext to the matching location under the shadow tree.

After decrypting, inspect both trees from Bob’s perspective:

```bash
find sandbox/bob -name 'plain.txt' | sort
# Output should list both datasite and shadow versions within Bob's tree
echo "Shadow contents:"
cat sandbox/bob/unencrypted/bob@example.org/shared/alice@example.org/files/plain.txt
```

## 6. Confirm Results

- Ciphertext: `sandbox/bob/datasites/bob@example.org/shared/alice@example.org/files/plain.txt`
- Decrypted plaintext: `sandbox/bob/unencrypted/bob@example.org/shared/alice@example.org/files/plain.txt`

Relative mode is ideal operating on a SyftBox datasite tree.
