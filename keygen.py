#!/usr/bin/env python3
"""
Module Name: keygen.py

Description:
    Ed25519 keypair generator for mutual authentication.
    Writes raw 32-byte key files:
      - <name>_ed25519       (private key seed, chmod 600)
      - <name>_ed25519.pub   (public key)
    Prints the 8-byte SHA-256 fingerprint for identification.

Author: John Burns
Date: 2025-05-02
Version: 4.0
"""

import argparse
import os
import stat

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from crypto_utils import compute_fingerprint


def main():
    parser = argparse.ArgumentParser(description="Generate Ed25519 keypair for DNS exfiltration authentication")
    parser.add_argument('--name', required=True, help='Key name prefix (e.g. "server", "client1")')
    parser.add_argument('--output-dir', default='.', help='Directory to write key files')
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    priv_key = Ed25519PrivateKey.generate()

    # Extract raw 32-byte seed (private key)
    priv_bytes = priv_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Extract raw 32-byte public key
    pub_bytes = priv_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    priv_path = os.path.join(args.output_dir, f"{args.name}_ed25519")
    pub_path = os.path.join(args.output_dir, f"{args.name}_ed25519.pub")

    with open(priv_path, 'wb') as f:
        f.write(priv_bytes)
    os.chmod(priv_path, stat.S_IRUSR | stat.S_IWUSR)  # 600

    with open(pub_path, 'wb') as f:
        f.write(pub_bytes)

    fingerprint = compute_fingerprint(priv_key.public_key()).hex()
    print(f"Keypair generated:")
    print(f"  Private key: {priv_path}")
    print(f"  Public key:  {pub_path}")
    print(f"  Fingerprint: {fingerprint}")


if __name__ == '__main__':
    main()
