#!/usr/bin/env python3
"""
keygen.py

Generate an X25519 key pair for DNS exfiltration with perfect forward secrecy,
save the private and public keys as raw 32-byte files, and append the public
key filename to a .env configuration file.

This script performs the following steps:
1. Creates a new ephemeral X25519 private key.
2. Derives the corresponding public key.
3. Writes the private key to `server.key` in raw (32-byte) format.
4. Writes the public key to `server_public.key` in raw (32-byte) format.
5. Appends a `SERVER_PUBLIC_KEY=server_public.key` entry to the `.env` file,
   so that the client and server code can automatically pick up the public key
   path from environment variables.

Usage:
    python keygen.py

Dependencies:
    cryptography

Author: John Burns
Date: 2025-05-07
Version: 2.5
"""

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

# Generate private key
private_key = x25519.X25519PrivateKey.generate()
public_key = private_key.public_key()

# Save private key (raw 32 bytes)
with open("server.key", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    ))

# Save public key (raw 32 bytes)
with open("server_public.key", "wb") as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ))

# Append to .env
with open(".env", "a") as f:
    f.write("SERVER_PUBLIC_KEY=server_public.key\n")
