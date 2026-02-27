#!/usr/bin/env python3
"""
Module Name: crypto_utils.py

Description:
    Shared cryptographic utilities for DNS exfiltration toolkit v4.
    Provides key I/O, Base32 encoding, HKDF key derivation, AES-GCM
    encryption/decryption, versioned wire format for key exchange,
    and optional JSON log formatting.

Author: John Burns
Date: 2026-02-27
Version: 4.0
"""

import base64
import hashlib
import json
import logging
import os
import struct
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Protocol version
PROTOCOL_VERSION = 1


# === Key I/O ===

def load_signing_key(path):
    """Load an Ed25519 private key from a raw 32-byte seed file."""
    with open(path, 'rb') as f:
        seed = f.read()
    return Ed25519PrivateKey.from_private_bytes(seed)


def load_identity_pubkey(path):
    """Load an Ed25519 public key from a raw 32-byte file."""
    with open(path, 'rb') as f:
        pub_bytes = f.read()
    return Ed25519PublicKey.from_public_bytes(pub_bytes)


def compute_fingerprint(pub_key):
    """Compute 8-byte fingerprint = SHA256(raw_pubkey)[:8]."""
    pub_bytes = pub_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return hashlib.sha256(pub_bytes).digest()[:8]


# === Base32 ===

def base32_encode(data):
    """Base32-encode bytes and strip padding."""
    return base64.b32encode(data).decode('ascii').rstrip('=')


def base32_decode(b32_string):
    """Base32-decode string, adding padding as needed."""
    pad_len = (8 - len(b32_string) % 8) % 8
    padded = b32_string.upper() + ('=' * pad_len)
    return base64.b32decode(padded)


# === HKDF Key Derivation ===

def derive_shared_keys(private_key, peer_pub_bytes, session_id, local_pub_bytes, peer_pub_bytes_raw):
    """
    Perform ECDH and derive AES-GCM key via HKDF.
    HKDF info is bound to session ID and both public keys for context separation.
    Returns a 32-byte AES key.
    """
    peer_pub = x25519.X25519PublicKey.from_public_bytes(peer_pub_bytes)
    shared_secret = private_key.exchange(peer_pub)
    # Canonical ordering: sort pubkeys so both sides derive the same key
    sorted_pubs = b''.join(sorted([local_pub_bytes, peer_pub_bytes_raw]))
    info = b'dns-exfil-v1|' + session_id.encode() + b'|' + sorted_pubs
    material = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info
    ).derive(shared_secret)
    return material


# === AES-GCM Encryption/Decryption (no HMAC) ===

def encrypt_file(file_path, aes_key):
    """
    Read file, encrypt with AES-GCM.
    Returns nonce(12) || ciphertext+tag.
    """
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return nonce + ciphertext


def decrypt_blob(aes_key, blob):
    """
    Decrypt AES-GCM blob (nonce || ciphertext+tag).
    Returns plaintext bytes.
    """
    nonce = blob[:12]
    ciphertext = blob[12:]
    return AESGCM(aes_key).decrypt(nonce, ciphertext, associated_data=None)


# === Wire Format (version byte + length-prefixed fields) ===

def encode_kex_payload(fields):
    """
    Encode key exchange payload:
      version(1) || num_fields(1) || [len(2) || data]...

    fields: list of bytes objects
    Returns bytes.
    """
    parts = [struct.pack('BB', PROTOCOL_VERSION, len(fields))]
    for field in fields:
        parts.append(struct.pack('>H', len(field)))
        parts.append(field)
    return b''.join(parts)


def decode_kex_payload(data):
    """
    Parse key exchange payload.
    Returns (version, list_of_fields).
    Raises ValueError on invalid data.
    """
    if len(data) < 2:
        raise ValueError("KEX payload too short")
    version, num_fields = struct.unpack('BB', data[:2])
    offset = 2
    fields = []
    for _ in range(num_fields):
        if offset + 2 > len(data):
            raise ValueError("KEX payload truncated (field length)")
        field_len = struct.unpack('>H', data[offset:offset + 2])[0]
        offset += 2
        if offset + field_len > len(data):
            raise ValueError("KEX payload truncated (field data)")
        fields.append(data[offset:offset + field_len])
        offset += field_len
    return version, fields


# === JSON Logging ===

class JSONFormatter(logging.Formatter):
    """Format log records as JSON lines."""

    def format(self, record):
        log_obj = {
            'timestamp': self.formatTime(record),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
        }
        if record.exc_info and record.exc_info[0]:
            log_obj['exception'] = self.formatException(record.exc_info)
        return json.dumps(log_obj)


def configure_logging(json_log=False):
    """Configure root logging with optional JSON output."""
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    # Remove existing handlers
    for handler in root.handlers[:]:
        root.removeHandler(handler)
    handler = logging.StreamHandler()
    if json_log:
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    root.addHandler(handler)
