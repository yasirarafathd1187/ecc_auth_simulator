"""Module 3 - mutual authentication and key exchange.

Message flow (client = device, server = verifier):

  1. Server -> Client : nonce_s                      (fresh random challenge)
  2. Client -> Server : device_id, nonce_s, nonce_c, eph_c, Sign_dev(CLIENT msg)
  3. Server -> Client : eph_s, Sign_srv(SERVER msg)
  4. Both             : shared = ECDH(eph_priv, peer_eph_pub)
                        keys   = HKDF-SHA256(shared, salt=nonce_s||nonce_c, info=H(transcript))
  5. Data             : AES-256-GCM with a per-direction key and a record counter

Both sides sign their own ephemeral key plus both nonces, so a man in the
middle cannot swap keys.  Ephemeral private keys are discarded after the
handshake, which gives forward secrecy.  The server's long-term key is
pinned in the client (no certificates in this simulator).
"""

from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass
from typing import Callable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import keys
from .registry import Registry

NONCE_LEN = 32
CHALLENGE_TTL_S = 30


class HandshakeError(Exception):
    """The handshake was rejected."""


class SessionError(Exception):
    """A protected record was rejected (replay, reorder or tampering)."""


# ---- signed messages (domain separated by role) ------------------------------

def _lp(*parts: bytes) -> bytes:
    """Length-prefix every field so concatenation is unambiguous."""
    return b"".join(len(p).to_bytes(2, "big") + p for p in parts)


def client_message(device_id: str, nonce_s: bytes, nonce_c: bytes, eph_c: bytes) -> bytes:
    return b"ECC-SIM-CLIENT-v1" + _lp(device_id.encode(), nonce_s, nonce_c, eph_c)


def server_message(device_id: str, nonce_s: bytes, nonce_c: bytes,
                   eph_c: bytes, eph_s: bytes) -> bytes:
    return b"ECC-SIM-SERVER-v1" + _lp(device_id.encode(), nonce_s, nonce_c, eph_c, eph_s)


def derive_keys(shared: bytes, nonce_s: bytes, nonce_c: bytes,
                srv_msg: bytes) -> tuple[bytes, bytes, bytes]:
    """Return (client->server key, server->client key, session id)."""
    okm = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=nonce_s + nonce_c,
        info=b"ECC-SIM-keys-v1" + hashlib.sha256(srv_msg).digest(),
    ).derive(shared)
    sid = hashlib.sha256(srv_msg).digest()[:8]
    return okm[:32], okm[32:], sid


# ---- wire messages --------------------------------------------------------------

@dataclass
class ClientHello:
    device_id: str
    nonce_s: bytes
    nonce_c: bytes
    eph_c: bytes        # uncompressed P-256 point
    signature: bytes


@dataclass
class ServerHello:
    eph_s: bytes
    signature: bytes


# ---- protected session -------------------------------------------------------------

class Session:
    """AES-256-GCM channel with strictly increasing record counters."""

    def __init__(self, send_key: bytes, recv_key: bytes, session_id: bytes):
        self.send_key, self.recv_key, self.session_id = send_key, recv_key, session_id
        self._send, self._recv = AESGCM(send_key), AESGCM(recv_key)
        self.send_ctr = 0
        self.recv_ctr = 0

    def seal(self, plaintext: bytes, aad: bytes = b"") -> tuple[int, bytes]:
        if not isinstance(plaintext, bytes) or not isinstance(aad, bytes):
            raise TypeError("plaintext and associated data must be bytes")
        if self.send_ctr >= 2**96:
            raise SessionError("record counter exhausted; establish a new session")
        ctr = self.send_ctr
        ciphertext = self._send.encrypt(ctr.to_bytes(12, "big"), plaintext, self.session_id + aad)
        self.send_ctr += 1
        return ctr, ciphertext

    def open(self, ctr: int, ciphertext: bytes, aad: bytes = b"") -> bytes:
        if not isinstance(ctr, int) or isinstance(ctr, bool) or ctr < 0 or ctr >= 2**96:
            raise SessionError("invalid record counter")
        if not isinstance(ciphertext, bytes) or not isinstance(aad, bytes):
            raise SessionError("ciphertext and associated data must be bytes")
        if ctr != self.recv_ctr:
            raise SessionError("replayed or out-of-order record")
        try:
            pt = self._recv.decrypt(ctr.to_bytes(12, "big"), ciphertext, self.session_id + aad)
        except InvalidTag as exc:
            raise SessionError("authentication tag check failed (tampered record)") from exc
        self.recv_ctr += 1
        return pt


# ---- server --------------------------------------------------------------------------

class Server:
    def __init__(self, registry: Registry, signing_key: ec.EllipticCurvePrivateKey,
                 now: Callable[[], float] = time.time, challenge_ttl: float = CHALLENGE_TTL_S):
        self.registry = registry
        self.signing_key = signing_key
        self._now = now
        self._ttl = challenge_ttl
        self._issued: dict[bytes, float] = {}

    @property
    def public_key(self) -> ec.EllipticCurvePublicKey:
        return self.signing_key.public_key()

    def new_challenge(self) -> bytes:
        nonce = os.urandom(NONCE_LEN)
        self._issued[nonce] = self._now()
        return nonce

    def _reject(self, device_id: str, reason: str):
        self.registry.log("auth_rejected", device_id, reason)
        raise HandshakeError(reason)

    def handle_client_hello(self, hello: ClientHello) -> tuple[ServerHello, Session]:
        # 1. the challenge must be one we issued, unused and fresh.  It is
        #    consumed immediately, so each challenge works exactly once.
        issued_at = self._issued.pop(hello.nonce_s, None)
        if issued_at is None:
            self._reject(hello.device_id, "unknown or already-used challenge (replay?)")
        if self._now() - issued_at > self._ttl:
            self._reject(hello.device_id, "challenge expired")
        # 2. the device must be registered, active and unexpired
        pub = self.registry.active_public_key(hello.device_id)
        if pub is None:
            self._reject(hello.device_id, "device unknown, revoked or key expired")
        # 3. the device's signature must cover its ephemeral key and both nonces
        msg = client_message(hello.device_id, hello.nonce_s, hello.nonce_c, hello.eph_c)
        if not keys.verify(pub, hello.signature, msg):
            self._reject(hello.device_id, "invalid device signature")
        try:
            eph_c_pub = keys.public_from_bytes(hello.eph_c)
        except keys.KeyError_:
            self._reject(hello.device_id, "invalid ephemeral public key")
        # 4. our ephemeral key, signed with the long-term server key
        eph_priv = keys.generate_keypair()
        eph_s = keys.public_bytes(eph_priv.public_key())
        srv_msg = server_message(hello.device_id, hello.nonce_s, hello.nonce_c, hello.eph_c, eph_s)
        sig = keys.sign(self.signing_key, srv_msg)
        shared = eph_priv.exchange(ec.ECDH(), eph_c_pub)
        k_c2s, k_s2c, sid = derive_keys(shared, hello.nonce_s, hello.nonce_c, srv_msg)
        del eph_priv  # forward secrecy: the ephemeral private key is dropped
        self.registry.log("auth_ok", hello.device_id, f"session={sid.hex()}")
        return ServerHello(eph_s, sig), Session(send_key=k_s2c, recv_key=k_c2s, session_id=sid)


# ---- client ------------------------------------------------------------------------------

class Client:
    def __init__(self, device_id: str, private_key: ec.EllipticCurvePrivateKey,
                 server_public_key: ec.EllipticCurvePublicKey):
        self.device_id = device_id
        self.private_key = private_key
        self.server_public_key = server_public_key   # pinned
        self._eph = None
        self._hello: ClientHello | None = None

    def start(self, nonce_s: bytes) -> ClientHello:
        self._eph = keys.generate_keypair()
        nonce_c = os.urandom(NONCE_LEN)
        eph_c = keys.public_bytes(self._eph.public_key())
        sig = keys.sign(self.private_key, client_message(self.device_id, nonce_s, nonce_c, eph_c))
        self._hello = ClientHello(self.device_id, nonce_s, nonce_c, eph_c, sig)
        return self._hello

    def finish(self, server_hello: ServerHello) -> Session:
        h = self._hello
        if h is None or self._eph is None:
            raise HandshakeError("start() must be called first")
        srv_msg = server_message(h.device_id, h.nonce_s, h.nonce_c, h.eph_c, server_hello.eph_s)
        if not keys.verify(self.server_public_key, server_hello.signature, srv_msg):
            raise HandshakeError("server signature invalid (wrong server or tampered key)")
        try:
            eph_s_pub = keys.public_from_bytes(server_hello.eph_s)
        except keys.KeyError_:
            raise HandshakeError("invalid server ephemeral key")
        shared = self._eph.exchange(ec.ECDH(), eph_s_pub)
        k_c2s, k_s2c, sid = derive_keys(shared, h.nonce_s, h.nonce_c, srv_msg)
        self._eph = None  # forward secrecy
        return Session(send_key=k_c2s, recv_key=k_s2c, session_id=sid)


def run_handshake(client: Client, server: Server) -> tuple[Session, Session]:
    """Run the full exchange in-process.  Returns (client session, server session)."""
    nonce_s = server.new_challenge()
    hello = client.start(nonce_s)
    server_hello, server_session = server.handle_client_hello(hello)
    client_session = client.finish(server_hello)
    return client_session, server_session
