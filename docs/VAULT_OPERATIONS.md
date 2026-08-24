# Vault operations guide

The `SessionVault` stores credential material (tickets, certificates,
hashes, keys) with Fernet encryption at rest. This guide covers key
management, day-to-day operations, and the threat model.

## Key management

### Generating a key

Generate a Fernet key from any Python environment:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Store the output in your secret manager. The key is a 44-character
URL-safe base64 string.

### Setting the key

Set `ADAF_SESSION_VAULT_KEY` before any vault operation:

```bash
export ADAF_SESSION_VAULT_KEY='<key-from-secret-manager>'
```

The key is never written to disk by ADAF-ATTACK. It must be present in the
environment for every `put` and `get` of secret material.

### Key rotation

ADAF-ATTACK does not perform automatic key rotation. To rotate:

1. Export all secret items from the vault with the current key.
2. Set the new key in `ADAF_SESSION_VAULT_KEY`.
3. Re-import the items. Each `put()` re-encrypts with the new key.
4. Verify all items decrypt correctly.
5. Retire the old key.

Because each session has its own vault directory, rotation is
per-session. Active engagement sessions should complete and package
evidence before rotating.

### Key recovery

If the key is lost, encrypted vault blobs (`.vault` files) cannot be
recovered. The public index (`vault/index.json`) still contains redacted
metadata — you can see what was stored but not decrypt it.

Mitigation: store the key in your organization's secret manager with
appropriate access controls and backup policies.

## Vault operations

### Storing material

```python
vault = session.vault()
vault.put(
    "tgt-operator",
    kind="ccache",
    value={"base64": "<base64-encoded-ccache>"},
    secret=True,
    metadata={"principal": "operator@CORP.LOCAL", "expires": "2026-08-24T00:00:00Z"},
)
```

- `name`: unique identifier within the session vault.
- `kind`: material type (`ccache`, `pfx`, `pem`, `nt_hash`, `aes_key`, `certificate`).
- `value`: the secret data (serialized as JSON before encryption).
- `secret`: when `True`, the value is Fernet-encrypted. When `False`, it
  is stored in the index as cleartext.
- `metadata`: public metadata written to the index after redaction.

### Retrieving material

```python
vault = session.vault()
value = vault.get("tgt-operator")
```

Requires `ADAF_SESSION_VAULT_KEY` in the environment.

### Listing items

```python
items = vault.list()
for item in items:
    print(f"{item.name}: {item.kind} (secret={item.secret})")
```

Listing does not require the encryption key — it reads only the public
index.

### Deleting material

```python
vault.delete("tgt-operator")  # single item
vault.purge_all()              # all items and blobs
```

### Checking existence

```python
if vault.exists("tgt-operator"):
    ...
```

## CLI operations

The `ticket-lifecycle` capability provides CLI access to vault operations:

```bash
# Import a ccache file into the vault
adaf-attack run ticket-lifecycle -d corp.local --dc-ip 10.0.0.10 \
  --operation import-ccache --artifact ./operator.ccache

# Import a PFX certificate
adaf-attack run ticket-lifecycle -d corp.local --dc-ip 10.0.0.10 \
  --operation import-pfx --artifact ./cert.pfx

# List vault contents
adaf-attack run credential-inventory -d corp.local --dc-ip 10.0.0.10
```

## Data model

### vault/index.json

```json
{
  "version": 1,
  "items": {
    "tgt-operator": {
      "kind": "ccache",
      "secret": true,
      "metadata": {"principal": "operator@CORP.LOCAL", "expires": "2026-08-24T00:00:00Z"},
      "file": "tgt-operator.vault"
    }
  }
}
```

- Metadata is redacted through the `operator` redaction profile before
  writing. Secret values (NT hashes, Kerberos blobs, PEM keys) are
  replaced with `[REDACTED]` in the index.
- The `file` field points to the encrypted blob relative to the vault
  directory.

### Encrypted blobs

Each `.vault` file contains a Fernet token (base64-encoded). The plaintext
is the JSON-serialized value passed to `put()`.

## Filesystem layout

```
<session>/vault/
├── index.json           # 0o600 — redacted public metadata
├── tgt-operator.vault   # 0o600 — Fernet-encrypted blob
└── cert-esc1.vault      # 0o600 — Fernet-encrypted blob
```

The vault directory is created with `0o700` permissions. Individual files
are restricted to `0o600`.

## Security properties

| Property | Implementation |
|----------|---------------|
| Encryption at rest | Fernet (AES-128-CBC + HMAC-SHA256) |
| Key storage | Environment variable only; never written to disk |
| Path traversal | `_safe_blob_path()` resolves and validates paths stay inside the vault |
| Symlink following | Rejected — symlinks in the vault directory raise `VaultError` |
| Index confidentiality | Metadata redacted via `redact()` before writing |
| Integrity | Fernet includes HMAC; `InvalidToken` on any corruption or wrong key |

## Threat model

| Threat | Mitigation |
|--------|------------|
| Disk access by unauthorized user | Fernet encryption; `0o600`/`0o700` permissions |
| Key in environment leaks via process listing | Use a secret manager injection (e.g., Vault agent, AWS Secrets Manager) rather than shell export in shared environments |
| Key loss | Vault blobs are irrecoverable; store key in a backed-up secret manager |
| Stale credentials in old sessions | Use `purge_all()` or `credential-inventory --operation purge` after engagement close |
| Vault index reveals material types | The index shows `kind` and redacted metadata; this is intentional for audit traceability |
