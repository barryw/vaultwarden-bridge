#!/usr/bin/env python3
"""Register a test account on Vaultwarden and seed it with test items via bw CLI."""

import hashlib
import base64
import hmac as hmac_mod
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


def pbkdf2(password: bytes, salt: bytes, iterations: int, dklen: int = 32) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password, salt, iterations, dklen=dklen)


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand (RFC 5869) with SHA-256."""
    hash_len = 32
    n = (length + hash_len - 1) // hash_len
    okm = b""
    t = b""
    for i in range(1, n + 1):
        t = hmac_mod.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]


def make_master_key() -> bytes:
    return pbkdf2(PASSWORD.encode("utf-8"), EMAIL.lower().encode("utf-8"), KDF_ITERATIONS)


def make_master_password_hash(master_key: bytes) -> str:
    return base64.b64encode(
        pbkdf2(master_key, PASSWORD.encode("utf-8"), 1)
    ).decode()


def stretch_key(master_key: bytes) -> tuple[bytes, bytes]:
    """Stretch master key into encryption key (32 bytes) and MAC key (32 bytes)
    using HKDF-Expand."""
    enc_key = hkdf_expand(master_key, b"enc", 32)
    mac_key = hkdf_expand(master_key, b"mac", 32)
    return enc_key, mac_key


def encrypt_aes_cbc(data: bytes, enc_key: bytes, mac_key: bytes) -> str:
    """Encrypt data with AES-256-CBC + HMAC-SHA256, return Bitwarden format string."""
    # PKCS7 padding
    pad_len = 16 - (len(data) % 16)
    padded = data + bytes([pad_len] * pad_len)

    iv = os.urandom(16)

    # AES-CBC encrypt via openssl
    proc = subprocess.run(
        ["openssl", "enc", "-aes-256-cbc", "-nosalt", "-nopad",
         "-K", enc_key.hex(), "-iv", iv.hex()],
        input=padded,
        capture_output=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"openssl enc failed: {proc.stderr.decode()}")
    ct = proc.stdout

    # HMAC-SHA256 over iv + ct
    mac = hmac_mod.new(mac_key, iv + ct, hashlib.sha256).digest()

    # Bitwarden format: "2.{b64_iv}|{b64_ct}|{b64_mac}"
    return "2.{}|{}|{}".format(
        base64.b64encode(iv).decode(),
        base64.b64encode(ct).decode(),
        base64.b64encode(mac).decode(),
    )


def generate_rsa_keypair(enc_key: bytes, mac_key: bytes) -> tuple[str, str]:
    """Generate RSA-2048 keypair. Return (public_key_b64, encrypted_private_key)."""
    # Generate RSA key
    proc = subprocess.run(
        ["openssl", "genpkey", "-algorithm", "RSA",
         "-pkeyopt", "rsa_keygen_bits:2048", "-outform", "DER"],
        capture_output=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"openssl genpkey failed: {proc.stderr.decode()}")
    private_der = proc.stdout

    # Extract public key
    proc = subprocess.run(
        ["openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"],
        input=private_der,
        capture_output=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"openssl pkey failed: {proc.stderr.decode()}")
    public_der = proc.stdout

    public_b64 = base64.b64encode(public_der).decode()
    encrypted_private = encrypt_aes_cbc(private_der, enc_key, mac_key)

    return public_b64, encrypted_private


def register_account():
    """Register an account using the Bitwarden-compatible API."""
    master_key = make_master_key()
    master_password_hash = make_master_password_hash(master_key)
    enc_key, mac_key = stretch_key(master_key)

    # Generate a 64-byte symmetric key (32 bytes enc + 32 bytes mac)
    sym_key = os.urandom(64)
    encrypted_sym_key = encrypt_aes_cbc(sym_key, enc_key, mac_key)

    # Generate RSA keypair
    public_key, encrypted_private_key = generate_rsa_keypair(enc_key, mac_key)

    payload = json.dumps({
        "name": "Bridge Test",
        "email": EMAIL,
        "masterPasswordHash": master_password_hash,
        "masterPasswordHint": "test",
        "key": encrypted_sym_key,
        "keys": {
            "publicKey": public_key,
            "encryptedPrivateKey": encrypted_private_key,
        },
        "kdf": 0,
        "kdfIterations": KDF_ITERATIONS,
    }).encode()

    req = urllib.request.Request(
        f"{VAULTWARDEN_URL}/identity/accounts/register",
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

    print(f"Login failed: stdout={result.stdout} stderr={result.stderr}", file=sys.stderr)
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
        print(f"  Failed '{name}': {result.stderr.strip()}")
    else:
        print(f"  Created: {name}")


def main():
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
