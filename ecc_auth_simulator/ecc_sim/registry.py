"""Module 1 - user and device registration (SQLite registry).

* Passwords are never stored: only a salted scrypt hash.
* A device must prove it holds the private key for the public key it
  registers (proof of possession: it signs a fresh registration challenge).
* Duplicate device IDs and duplicate public keys are rejected.
* Keys can be revoked or rotated; every decision is written to an event log.
"""

from __future__ import annotations

import os
import sqlite3
import time
from typing import Callable

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from . import keys

SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**14, 8, 1
MIN_PASSWORD_LEN = 8
KEY_LIFETIME_S = 365 * 24 * 3600
REG_CHALLENGE_TTL_S = 120


class RegistryError(Exception):
    """A registration, rotation or revocation request was rejected."""


def _kdf(salt: bytes) -> Scrypt:
    return Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)


def hash_password(password: str) -> tuple[bytes, bytes]:
    salt = os.urandom(16)
    return salt, _kdf(salt).derive(password.encode())


def check_password(password: str, salt: bytes, expected: bytes) -> bool:
    try:
        _kdf(salt).verify(password.encode(), expected)  # constant-time compare
        return True
    except InvalidKey:
        return False


def proof_message(device_id: str, nonce: bytes) -> bytes:
    """What a device signs to prove it holds the private key."""
    return b"ECC-SIM-REGISTER-v1|" + device_id.encode() + b"|" + nonce


class Registry:
    SCHEMA = """
    CREATE TABLE IF NOT EXISTS devices (
        device_id    TEXT PRIMARY KEY,
        user_id      TEXT NOT NULL,
        pw_salt      BLOB NOT NULL,
        pw_hash      BLOB NOT NULL,
        public_pem   BLOB NOT NULL,
        fingerprint  TEXT NOT NULL UNIQUE,
        key_version  INTEGER NOT NULL DEFAULT 1,
        status       TEXT NOT NULL DEFAULT 'active',
        created_at   REAL NOT NULL,
        expires_at   REAL NOT NULL
    );
    CREATE TABLE IF NOT EXISTS events (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        ts        REAL NOT NULL,
        event     TEXT NOT NULL,
        device_id TEXT,
        detail    TEXT
    );
    """

    def __init__(self, path: str = ":memory:", now: Callable[[], float] = time.time):
        # Streamlit reruns may access session-scoped objects from a different
        # ScriptRunner thread. Permit cross-thread use of this per-session
        # connection; each session executes its script sequentially.
        self.db = sqlite3.connect(path, timeout=30, check_same_thread=False)
        self.db.execute("PRAGMA busy_timeout = 30000")
        self.db.executescript(self.SCHEMA)
        self._now = now
        self._challenges: dict[bytes, float] = {}

    # ---- event log -------------------------------------------------------
    def log(self, event: str, device_id: str | None = None, detail: str = "") -> None:
        self.db.execute(
            "INSERT INTO events (ts, event, device_id, detail) VALUES (?,?,?,?)",
            (self._now(), event, device_id, detail),
        )
        self.db.commit()

    def events(self) -> list[tuple]:
        cur = self.db.execute("SELECT id, event, device_id, detail FROM events ORDER BY id")
        return cur.fetchall()

    # ---- registration challenge -------------------------------------------
    def new_registration_challenge(self) -> bytes:
        nonce = os.urandom(16)
        self._challenges[nonce] = self._now() + REG_CHALLENGE_TTL_S
        return nonce

    def _consume_challenge(self, nonce: bytes) -> None:
        expiry = self._challenges.pop(nonce, None)  # single use
        if expiry is None:
            raise RegistryError("unknown or already-used registration challenge")
        if self._now() > expiry:
            raise RegistryError("registration challenge expired")

    def _check_proof(self, device_id, public_key, nonce, proof) -> None:
        self._consume_challenge(nonce)
        if not keys.verify(public_key, proof, proof_message(device_id, nonce)):
            raise RegistryError("proof of possession of the private key failed")

    # ---- register -----------------------------------------------------------
    def register(self, user_id, device_id, password, public_key, nonce, proof):
        """Register a device.  Returns the stored identity record (a dict)."""
        try:
            if not user_id or not device_id:
                raise RegistryError("user ID and device ID are required")
            if len(password) < MIN_PASSWORD_LEN:
                raise RegistryError(f"password shorter than {MIN_PASSWORD_LEN} characters")
            self._check_proof(device_id, public_key, nonce, proof)
            if self.get_device(device_id) is not None:
                raise RegistryError("duplicate device ID")
            fp = keys.fingerprint(public_key)
            row = self.db.execute(
                "SELECT device_id FROM devices WHERE fingerprint=?", (fp,)
            ).fetchone()
            if row:
                raise RegistryError("public key already registered to another device")
            salt, pw_hash = hash_password(password)
            now = self._now()
            self.db.execute(
                "INSERT INTO devices (device_id,user_id,pw_salt,pw_hash,public_pem,"
                "fingerprint,created_at,expires_at) VALUES (?,?,?,?,?,?,?,?)",
                (device_id, user_id, salt, pw_hash, keys.public_pem(public_key), fp,
                 now, now + KEY_LIFETIME_S),
            )
            self.db.commit()
        except RegistryError as exc:
            self.log("register_rejected", device_id, str(exc))
            raise
        self.log("register_ok", device_id, f"user={user_id} fp={fp[:16]}")
        return self.get_device(device_id)

    # ---- lookups ----------------------------------------------------------------
    def get_device(self, device_id: str) -> dict | None:
        row = self.db.execute(
            "SELECT device_id,user_id,public_pem,fingerprint,key_version,status,"
            "created_at,expires_at FROM devices WHERE device_id=?",
            (device_id,),
        ).fetchone()
        if row is None:
            return None
        names = ("device_id", "user_id", "public_pem", "fingerprint", "key_version",
                 "status", "created_at", "expires_at")
        return dict(zip(names, row))

    def active_public_key(self, device_id: str):
        """Public key of an active, unexpired device, else None."""
        rec = self.get_device(device_id)
        if rec is None or rec["status"] != "active" or self._now() > rec["expires_at"]:
            return None
        return keys.public_from_pem(rec["public_pem"])

    def verify_password(self, device_id: str, password: str) -> bool:
        row = self.db.execute(
            "SELECT pw_salt, pw_hash FROM devices WHERE device_id=?", (device_id,)
        ).fetchone()
        if row is None:
            return False
        return check_password(password, row[0], row[1])

    # ---- revoke / rotate ---------------------------------------------------------
    def revoke(self, device_id: str, reason: str = "") -> None:
        if self.get_device(device_id) is None:
            raise RegistryError("unknown device")
        self.db.execute("UPDATE devices SET status='revoked' WHERE device_id=?", (device_id,))
        self.db.commit()
        self.log("revoked", device_id, reason)

    def rotate(self, device_id, password, new_public_key, nonce, proof):
        """Replace a device's key.  Needs the password and proof of the NEW key."""
        rec = self.get_device(device_id)
        if rec is None or rec["status"] != "active":
            raise RegistryError("unknown or inactive device")
        if not self.verify_password(device_id, password):
            self.log("rotate_rejected", device_id, "bad password")
            raise RegistryError("password check failed")
        try:
            self._check_proof(device_id, new_public_key, nonce, proof)
        except RegistryError as exc:
            self.log("rotate_rejected", device_id, str(exc))
            raise
        fp = keys.fingerprint(new_public_key)
        if fp == rec["fingerprint"]:
            raise RegistryError("new key is identical to the current key")
        # A rotated key must remain globally unique, just like an enrolled key.
        duplicate = self.db.execute(
            "SELECT device_id FROM devices WHERE fingerprint=? AND device_id<>?",
            (fp, device_id),
        ).fetchone()
        if duplicate:
            self.log("rotate_rejected", device_id, "public key already belongs to another device")
            raise RegistryError("public key already registered to another device")
        now = self._now()
        self.db.execute(
            "UPDATE devices SET public_pem=?, fingerprint=?, key_version=key_version+1,"
            " expires_at=? WHERE device_id=?",
            (keys.public_pem(new_public_key), fp, now + KEY_LIFETIME_S, device_id),
        )
        self.db.commit()
        self.log("rotated", device_id, f"new fp={fp[:16]}")
        return self.get_device(device_id)


def enroll(registry: Registry, user_id: str, device_id: str, password: str = "correct-horse-1",
           private_key=None):
    """Convenience helper: generate a key, prove possession, register.

    Returns (private_key, record).
    """
    priv = private_key or keys.generate_keypair()
    nonce = registry.new_registration_challenge()
    proof = keys.sign(priv, proof_message(device_id, nonce))
    record = registry.register(user_id, device_id, password, priv.public_key(), nonce, proof)
    return priv, record
