#!/usr/bin/env python3
"""Register a test account on Vaultwarden and seed it with test items via bw CLI."""

import hashlib
import base64
import json
import os
import subprocess
import sys
import urllib.request
import urllib.error

VAULTWARDEN_URL = os.environ.get("VAULTWARDEN_URL", "http://vaultwarden:80")
EMAIL = os.environ.get("TEST_EMAIL", "bridge-test@example.com")
PASSWORD = os.environ.get("TEST_PASSWORD", "TestPassword123!")
KDF_ITERATIONS = 600000


def pbkdf2(password: bytes, salt: bytes, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password, salt, iterations, dklen=32)


def register_account():
    """Register an account using the Bitwarden-compatible API."""
    master_key = pbkdf2(PASSWORD.encode(), EMAIL.lower().encode(), KDF_ITERATIONS)
    master_password_hash = base64.b64encode(
        pbkdf2(master_key, PASSWORD.encode(), 1)
    ).decode()

    # Generate a 64-byte symmetric key and encrypt it with master key (simplified)
    # For Vaultwarden, we need a properly formatted encrypted key
    sym_key = os.urandom(64)

    # Bitwarden encryption format: type.iv|ct|mac (type 2 = AES-CBC-256 + HMAC-SHA256)
    import hmac
    from hashlib import sha256

    # Stretch master key into enc_key (32 bytes) and mac_key (32 bytes)
    enc_key = pbkdf2(master_key, b"enc", 1)
    mac_key = pbkdf2(master_key, b"mac", 1)

    # AES-CBC encrypt the symmetric key
    # We need to pad the symmetric key to AES block size
    from struct import pack

    pad_len = 16 - (len(sym_key) % 16)
    padded = sym_key + bytes([pad_len] * pad_len)

    iv = os.urandom(16)

    # Pure Python AES-CBC is complex; use openssl via subprocess
    proc = subprocess.run(
        ["openssl", "enc", "-aes-256-cbc", "-nosalt", "-nopad",
         "-K", enc_key.hex(), "-iv", iv.hex()],
        input=padded,
        capture_output=True,
    )
    ct = proc.stdout

    # HMAC
    mac = hmac.new(mac_key, iv + ct, sha256).digest()

    # Format: "2.{base64_iv}|{base64_ct}|{base64_mac}"
    encrypted_key = "2.{}|{}|{}".format(
        base64.b64encode(iv).decode(),
        base64.b64encode(ct).decode(),
        base64.b64encode(mac).decode(),
    )

    payload = json.dumps({
        "name": "Bridge Test",
        "email": EMAIL,
        "masterPasswordHash": master_password_hash,
        "masterPasswordHint": "test",
        "key": encrypted_key,
        "kdf": 0,
        "kdfIterations": KDF_ITERATIONS,
    }).encode()

    req = urllib.request.Request(
        f"{VAULTWARDEN_URL}/api/accounts/register",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req) as resp:
            print(f"==> Account registered (status {resp.status})")
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        if "already exists" in body.lower() or e.code == 400:
            print(f"==> Account may already exist: {body}")
        else:
            print(f"==> Registration failed ({e.code}): {body}", file=sys.stderr)
            sys.exit(1)


def bw_login() -> str:
    """Login with bw CLI and return session key."""
    result = subprocess.run(
        ["bw", "login", EMAIL, PASSWORD, "--raw"],
        capture_output=True, text=True,
        env={**os.environ, "BW_NOINTERACTION": "true"},
    )
    if result.returncode == 0 and result.stdout.strip():
        return result.stdout.strip()

    # Try unlock if already logged in
    result = subprocess.run(
        ["bw", "unlock", PASSWORD, "--raw"],
        capture_output=True, text=True,
        env={**os.environ, "BW_NOINTERACTION": "true"},
    )
    if result.returncode == 0 and result.stdout.strip():
        return result.stdout.strip()

    print(f"Login failed: {result.stderr}", file=sys.stderr)
    sys.exit(1)


def bw_create_item(session: str, name: str, username: str, password: str):
    """Create a login item."""
    item = json.dumps({
        "type": 1,
        "name": name,
        "login": {"username": username, "password": password},
    })

    encode_result = subprocess.run(
        ["bw", "encode"],
        input=item, capture_output=True, text=True,
        env={**os.environ, "BW_SESSION": session},
    )

    result = subprocess.run(
        ["bw", "create", "item", encode_result.stdout.strip()],
        capture_output=True, text=True,
        env={**os.environ, "BW_SESSION": session},
    )
    if result.returncode != 0:
        print(f"Failed to create '{name}': {result.stderr}", file=sys.stderr)
    else:
        print(f"  Created: {name}")


def main():
    # Configure bw CLI
    subprocess.run(["bw", "config", "server", VAULTWARDEN_URL], capture_output=True)

    print("==> Registering account...")
    register_account()

    print("==> Logging in...")
    session = bw_login()
    print("==> Login successful")

    print("==> Creating test items...")
    items = [
        ("prod/db/password", "db_admin", "super-secret-db-password"),
        ("prod/api/token", "api-service", "api-token-12345"),
        ("staging/db/password", "db_staging", "staging-db-password"),
        ("denied-secret", "nope", "you-shall-not-pass"),
    ]
    for name, username, password in items:
        bw_create_item(session, name, username, password)

    subprocess.run(
        ["bw", "sync"],
        env={**os.environ, "BW_SESSION": session},
        capture_output=True,
    )
    print(f"==> Seeded {len(items)} test items")


if __name__ == "__main__":
    main()
