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

import os

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

# Write .env with both keys, replacing any existing entries
env_path = ".env"
env_vars = {
    "SERVER_PRIVATE_KEY": "server.key",
    "SERVER_PUBLIC_KEY": "server_public.key",
}

# Read existing .env lines, filtering out keys we're about to write
existing_lines = []
if os.path.exists(env_path):
    with open(env_path, "r") as f:
        existing_lines = [
            line for line in f.readlines()
            if not any(line.startswith(k + "=") for k in env_vars)
        ]

with open(env_path, "w") as f:
    f.writelines(existing_lines)
    for k, v in env_vars.items():
        f.write(f"{k}={v}\n")

print("Generated server.key and server_public.key")
print(f"Updated {env_path} with SERVER_PRIVATE_KEY and SERVER_PUBLIC_KEY")
