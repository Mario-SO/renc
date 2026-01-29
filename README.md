# renc

Rust Encryption Engine (CLI + library) that mirrors the `zenc` file format and behavior.

## Usage

Generate a keypair:

```bash
renc keygen
```

Encrypt with a password (password read from stdin):

```bash
printf "my password" | renc encrypt ./file.txt --password
```

Encrypt to a recipient public key (base64 Ed25519 public key):

```bash
renc encrypt ./file.txt --to <base64_pubkey>
```

Decrypt (secret read from stdin; password or secret key depends on file mode):

```bash
printf "my password" | renc decrypt ./file.txt.renc
```

## JSON Events

Each command emits one JSON object per line to stdout:

- `start`: `{ "event":"start", "file":"<path>", "size":<u64> }`
- `progress`: `{ "event":"progress", "bytes":<u64>, "percent":<f64> }`
- `done`: `{ "event":"done", "output":"<path>", "hash":"<sha256-hex>" }`
- `error`: `{ "event":"error", "code":"<string>", "message":"<string>" }`
- `keygen`: `{ "event":"keygen", "public_key":"<base64>", "secret_key":"<base64>" }`

## File Format (v1)

Header layout (fixed 90 bytes):

```
Magic (4) | Version (1) | Mode (1) | KDF params (12) | Salt (16) | Ephemeral pubkey (32) | Nonce (24)
```

- Magic: ASCII `RENC`
- Mode: `0x01` password, `0x02` pubkey
- KDF params: mem KiB (u32 LE), iterations (u32 LE), parallelism (u32 LE)
- Nonce: 24-byte XChaCha20 nonce

Payload:

- 64KB plaintext chunks
- Each chunk encrypted with XChaCha20-Poly1305
- 16-byte tag per chunk
- Associated data: header padded to 256 bytes + chunk index (u64 LE)
- Nonce per chunk: XOR chunk index into last 8 bytes of base nonce

## Library API

Public entry points are available in `src/lib.rs`:

- `generate_keypair()`
- `encrypt_file_with_password(...)`
- `encrypt_file_with_pubkey(...)`
- `decrypt_file_with_password(...)`
- `decrypt_file_with_secret(...)`

All functions return a `DoneInfo` containing output path and plaintext SHA-256.
