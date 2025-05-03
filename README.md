# DNS Exfiltration Server

This is a DNS exfiltration server designed to receive encrypted file fragments via DNS A record queries. The system supports encrypted and authenticated transmission using modern cryptographic primitives.

## 🔐 Key Features

- **Perfect Forward Secrecy (PFS)** via ephemeral Elliptic Curve Diffie-Hellman (ECDH) using X25519
- **Authenticated encryption** using AES-GCM with derived session keys
- **Base32 encoding** for DNS-safe payloads
- **UDP DNS server** that reassembles fragments and decrypts payloads on the fly
- **Stateless file-based session reassembly** keyed by client ephemeral identifier
- **Replay-resilient per-transfer encryption context** via ECDH

---

## 🔧 How It Works

1. **Key Exchange (ECDH):**
   - Each client generates a new ephemeral X25519 key pair.
   - The client sends its public key in Base32 chunks encoded in the DNS query (using chunk `0-0`).
   - The server derives a shared secret using its private key and the client's public key.
   - This secret is passed through an HKDF (HMAC-based Key Derivation Function) to produce a 256-bit AES-GCM key.

2. **Encrypted Data Transfer:**
   - The client encrypts the file using the derived AES key with a 12-byte random nonce.
   - The ciphertext is Base32-encoded (unpadded), then split into DNS-safe segments.
   - Each segment is sent as a query of the format:
     ```
     <id>-<index>-<total>-<chunk>.<domain>
     ```

3. **Decryption and Reassembly:**
   - When all chunks are received, the server Base32-decodes and AES-decrypts the full payload.
   - The decrypted binary is saved to disk under the `output/` directory.

---

## 📂 Environment Variables

Create a `.env` file in the root directory:

```ini
SERVER_PRIVATE_KEY=server.key
```

The private key should be a 32-byte raw X25519 key. You can generate one with Python:

```bash
python -c "from cryptography.hazmat.primitives.asymmetric import x25519; from cryptography.hazmat.primitives import serialization; key = x25519.X25519PrivateKey.generate(); open('server.key', 'wb').write(key.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption()))"
```

This file will be used automatically unless overridden with `--server-key`.

---

## 🚀 Running the Server

```bash
python server.py --port 5300 --domain xf.example.com
```

Alternatively, provide your server key via `.env`.

---

## 🔐 Cryptographic Design: Ephemeral Key Exchange

This system is designed with **Perfect Forward Secrecy** in mind:

- Clients generate a fresh X25519 ephemeral key for each file transfer.
- The server's static private key (provided via `.env`) is used to derive a shared secret.
- This secret is then fed into an HKDF to derive a per-transfer AES-GCM key.
- The AES key is used only once — for the current file transfer.

This ensures that even if a long-term key is compromised, past data cannot be decrypted.

---

## ⚠️ Notes on Security

- Every transfer uses a fresh ephemeral keypair, ensuring **forward secrecy**.
- AES-GCM provides **integrity and confidentiality**.
- Replay protection and client authentication are not currently implemented — consider adding HMAC or signatures for production scenarios.
- Sessions are ephemeral and stateless beyond active memory — no persistent logs are maintained.

---

## 📁 Output

Decrypted files are saved to the output directory (`--output-dir`, default: `output/`).

---

## 🧪 Interoperability

This server is designed to interoperate with the [Python or Go-based DNS exfiltration client](https://github.com/bufo333/python-dns-exfiltration-client-server), provided they conform to the same key-exchange and chunking conventions.

---

## 🛠️ Options

```bash
usage: server.py [-h] [--port PORT] [--output-dir DIR] [--low LOW] [--high HIGH] [--domain DOMAIN] [--server-key PATH]
```

---

## 👤 Author

John Burns — 2025-05-02  
Version 2.2