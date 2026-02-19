# SbC CLI Tutorial – Alice ↔ Bob Walkthrough

This tutorial mirrors the end-to-end flow exercised by the automated integration test and ` just test-integration-cli`. You will:

1. Prepare a sandbox directory with separate vault, datasite, and shadow roots for Alice and Bob.
2. Generate key material and export public bundles.
3. Encrypt a plaintext file for Bob, deliver it, inspect the ciphertext, and decrypt it.

All shell commands are relative to the repository root (`syftbox-crypto`). Adjust paths if your checkout lives elsewhere.

> Quick start: `just init-sandbox` will create the directory skeletons, write the datasite configs, and generate the Alice/Bob key material automatically. The steps below show the same process manually in case you need to customise the layout.

## 0. Compile / Run sbc

The `sbc` command can be run direcly from the repo root by invoking it as a binary sbc (this is a wrapper shell script).

Alternatively you can build and install with:

```
cargo install --path cli
which -a sbc
```

---

## 1. Prepare the Sandbox Layout

```bash
mkdir -p sandbox/alice/.sbc/{config,keys,bundles}
mkdir -p sandbox/alice/unencrypted/alice@example.org/{public/crypto,shared/bob@example.org/files}
mkdir -p sandbox/alice/datasites/alice@example.org/{public/crypto,shared/bob@example.org/files}

mkdir -p sandbox/bob/.sbc/{config,keys,bundles}
mkdir -p sandbox/bob/unencrypted/bob@example.org/{public/crypto,shared/alice@example.org/files}
mkdir -p sandbox/bob/datasites/bob@example.org/{public/crypto,shared/alice@example.org/files}
```

Skip this manual setup if you already used `just init-sandbox`.

## 2. Configure Datasite Roots

Create `config/datasite.json` for each identity so `sbc` knows where the encrypted (datasites) and shadow (unencrypted) trees live. The paths mirror those in the integration test.

```bash
cat > sandbox/alice/.sbc/config/datasite.json <<'JSON'
{
  "encrypted_root": "../datasites",
  "shadow_root": "../unencrypted"
}
JSON

cat > sandbox/bob/.sbc/config/datasite.json <<'JSON'
{
  "encrypted_root": "../datasites",
  "shadow_root": "../unencrypted"
}
JSON
```

If you ran `just init-sandbox`, these files already exist.

## 3. Seed Alice’s Plaintext Message

```bash
cat > sandbox/alice/unencrypted/alice@example.org/shared/bob@example.org/files/message.txt <<'TEXT'
Hello Bob,

This is a sample message from Alice. It will be encrypted for recipients.
TEXT
```

## 4. Generate Keys and Export Bundles

You can skip this section if you already ran `just init-sandbox`; re-running the commands is safe thanks to `--overwrite`.

### Alice

```bash
sbc \
  --vault sandbox/alice/.sbc \
  key generate \
  --identity alice@example.org \
  --overwrite \
  --bundle-out alice@example.org/public/crypto/did.json
```

### Bob

```bash
sbc \
  --vault sandbox/bob/.sbc \
  key generate \
  --identity bob@example.org \
  --overwrite \
  --bundle-out bob@example.org/public/crypto/did.json
```

## 4.1 Cache Each Other’s Public Bundles (TOFU)

Copy the public bundle into the recipient’s datasite tree and register it in the vault. This pins the counterparty fingerprint so `sbc file inspect` can flag tampering later.

```bash
# Share Alice’s bundle with Bob
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

Now do the reciprocal copy/import so Alice trusts Bob’s bundle:

```bash
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

Use `--force` if you intentionally overwrite a cached bundle (e.g., after rotating keys).

## 5. Encrypt Alice’s Message for Bob

```bash
sbc \
  --vault sandbox/alice/.sbc \
  file encrypt \
  --relative alice@example.org/shared/bob@example.org/files/message.txt \
  --recipient bob@example.org \
  --sender alice@example.org
```

The ciphertext now lives at `sandbox/alice/datasites/alice@example.org/shared/bob@example.org/files/message.txt`.

## 6. Deliver Ciphertext to Bob

```bash
cp \
  sandbox/alice/datasites/alice@example.org/shared/bob@example.org/files/message.txt \
  sandbox/bob/datasites/bob@example.org/shared/alice@example.org/files/message.txt
```

## 7. Inspect Ciphertext as Bob

```bash
sbc \
  --vault sandbox/bob/.sbc \
  file inspect \
  --input bob@example.org/shared/alice@example.org/files/message.txt \
  --identity bob@example.org \
  --verbose
```

You should see the `SBC1` magic, the sender (`alice@example.org`), the recipient list, and cipher statistics without the tool touching the payload bytes.

## 8. Decrypt into Bob’s Shadow Tree

```bash
sbc \
  --vault sandbox/bob/.sbc \
  file decrypt \
  --relative bob@example.org/shared/alice@example.org/files/message.txt \
  --identity bob@example.org
```

The decrypted plaintext resides at `sandbox/bob/unencrypted/bob@example.org/shared/alice@example.org/files/message.txt`.

---

## Verify Artefacts

- Private keys:
  `sandbox/alice/.sbc/keys/alice@example.org.key`
  `sandbox/bob/.sbc/keys/bob@example.org.key`

- Public bundles:
  `sandbox/alice/datasites/alice@example.org/public/crypto/did.json`
  `sandbox/bob/datasites/bob@example.org/public/crypto/did.json`

- Ciphertext envelope:
  `sandbox/bob/datasites/bob@example.org/shared/alice@example.org/files/message.txt`

- Decrypted plaintext:
  `sandbox/bob/unencrypted/bob@example.org/shared/alice@example.org/files/message.txt`

Repeat the same steps for other identities or add additional plaintext files under the corresponding `unencrypted/<identity>/shared/...` folders.\*\*\*
