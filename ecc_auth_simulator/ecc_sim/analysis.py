"""Module 4 - security analysis and performance evaluation.

* 14 attack scenarios, each run against a fresh registry and server.
* ECC P-256 versus RSA-2048 and RSA-3072: timing and size.
"""

from __future__ import annotations

import os
import statistics
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import keys
from .handshake import (
    Client, ClientHello, HandshakeError, Server, ServerHello, SessionError,
    client_message, derive_keys, run_handshake, server_message,
)
from .registry import Registry, enroll


class Clock:
    """Controllable clock so expiry can be tested without waiting."""

    def __init__(self):
        self.t = 1_700_000_000.0

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


class Env:
    """A registry, a server and one honestly enrolled device."""

    def __init__(self, device_id: str = "dev-001"):
        self.clock = Clock()
        self.registry = Registry(":memory:", now=self.clock)
        self.server_key = keys.generate_keypair()
        self.server = Server(self.registry, self.server_key, now=self.clock)
        self.device_id = device_id
        self.device_key, _ = enroll(self.registry, "alice", device_id)
        self.client = Client(device_id, self.device_key, self.server.public_key)

    def fresh_client(self) -> Client:
        return Client(self.device_id, self.device_key, self.server.public_key)


def _rejects(fn, *exc_types) -> tuple[bool, str]:
    """Run fn(); return (True, message) if it raised one of exc_types."""
    try:
        fn()
    except exc_types as exc:
        return True, str(exc)
    return False, "no error raised"


# ---------------------------------------------------------------------------
# 14 attack scenarios.  Each returns (passed: bool, observed: str).
# ---------------------------------------------------------------------------

def s_replay_hello():
    e = Env()
    nonce = e.server.new_challenge()
    hello = e.client.start(nonce)
    e.server.handle_client_hello(hello)                      # legitimate use
    ok, msg = _rejects(lambda: e.server.handle_client_hello(hello), HandshakeError)
    return ok, msg


def s_replay_record():
    e = Env()
    cs, ss = run_handshake(e.client, e.server)
    ctr, ct = cs.seal(b"transfer 100")
    ss.open(ctr, ct)                                         # delivered once
    return _rejects(lambda: ss.open(ctr, ct), SessionError)


def s_stale_challenge():
    e = Env()
    nonce = e.server.new_challenge()
    hello = e.client.start(nonce)
    e.clock.advance(31)                                      # TTL is 30 s
    return _rejects(lambda: e.server.handle_client_hello(hello), HandshakeError)


def s_forged_challenge():
    e = Env()
    hello = e.client.start(os.urandom(32))                   # never issued by the server
    return _rejects(lambda: e.server.handle_client_hello(hello), HandshakeError)


def s_impersonation_wrong_key():
    e = Env()
    attacker = Client(e.device_id, keys.generate_keypair(), e.server.public_key)
    hello = attacker.start(e.server.new_challenge())
    return _rejects(lambda: e.server.handle_client_hello(hello), HandshakeError)


def s_unregistered_device():
    e = Env()
    rogue = Client("dev-999", keys.generate_keypair(), e.server.public_key)
    hello = rogue.start(e.server.new_challenge())
    return _rejects(lambda: e.server.handle_client_hello(hello), HandshakeError)


def s_revoked_device():
    e = Env()
    e.registry.revoke(e.device_id, "device reported stolen")
    hello = e.client.start(e.server.new_challenge())
    return _rejects(lambda: e.server.handle_client_hello(hello), HandshakeError)


def s_mitm_client_key_swap():
    e = Env()
    hello = e.client.start(e.server.new_challenge())
    attacker_eph = keys.public_bytes(keys.generate_keypair().public_key())
    forged = ClientHello(hello.device_id, hello.nonce_s, hello.nonce_c, attacker_eph, hello.signature)
    return _rejects(lambda: e.server.handle_client_hello(forged), HandshakeError)


def s_mitm_server_key_swap():
    e = Env()
    hello = e.client.start(e.server.new_challenge())
    sh, _ = e.server.handle_client_hello(hello)
    attacker_eph = keys.public_bytes(keys.generate_keypair().public_key())
    forged = ServerHello(attacker_eph, sh.signature)
    return _rejects(lambda: e.client.finish(forged), HandshakeError)


def s_rogue_server():
    e = Env()
    hello = e.client.start(e.server.new_challenge())
    attacker_key = keys.generate_keypair()
    eph = keys.generate_keypair()
    eph_s = keys.public_bytes(eph.public_key())
    msg = server_message(hello.device_id, hello.nonce_s, hello.nonce_c, hello.eph_c, eph_s)
    forged = ServerHello(eph_s, keys.sign(attacker_key, msg))   # signed with the wrong key
    return _rejects(lambda: e.client.finish(forged), HandshakeError)


def s_tampered_ciphertext():
    e = Env()
    cs, ss = run_handshake(e.client, e.server)
    ctr, ct = cs.seal(b"pay alice 10")
    bad = bytearray(ct)
    bad[0] ^= 0x01
    return _rejects(lambda: ss.open(ctr, bytes(bad)), SessionError)


def s_cross_role_signature():
    """A signature made for the CLIENT role must not verify as a SERVER message."""
    e = Env()
    hello = e.client.start(e.server.new_challenge())
    srv_msg = server_message(hello.device_id, hello.nonce_s, hello.nonce_c, hello.eph_c, hello.eph_c)
    accepted = keys.verify(e.device_key.public_key(), hello.signature, srv_msg)
    return (not accepted), ("signature rejected for the other role" if not accepted
                            else "signature accepted across roles")


def s_forward_secrecy():
    """Attacker records a session, later steals BOTH long-term private keys."""
    e = Env()
    nonce = e.server.new_challenge()
    hello = e.client.start(nonce)
    sh, ss = e.server.handle_client_hello(hello)
    cs = e.client.finish(sh)
    ctr, ct = cs.seal(b"old secret message")
    srv_msg = server_message(hello.device_id, hello.nonce_s, hello.nonce_c, hello.eph_c, sh.eph_s)
    sid = derive_keys(b"\x00" * 32, hello.nonce_s, hello.nonce_c, srv_msg)[2]
    guesses = [
        e.device_key.exchange(ec.ECDH(), keys.public_from_bytes(sh.eph_s)),
        e.server_key.exchange(ec.ECDH(), keys.public_from_bytes(hello.eph_c)),
    ]
    for shared in guesses:
        k_c2s, _, _ = derive_keys(shared, hello.nonce_s, hello.nonce_c, srv_msg)
        try:
            AESGCM(k_c2s).decrypt(ctr.to_bytes(12, "big"), ct, sid)
            return False, "old session decrypted with long-term keys"
        except InvalidTag:
            continue
    return True, "old session stays secret even with both long-term keys"


def s_challenge_burn():
    """Known limit: challenges are sent in the clear, so an observer can burn one."""
    e = Env()
    nonce = e.server.new_challenge()
    attacker = Client(e.device_id, keys.generate_keypair(), e.server.public_key)
    burn = attacker.start(nonce)                             # attacker saw the challenge
    attacker_rejected, _ = _rejects(lambda: e.server.handle_client_hello(burn), HandshakeError)
    victim_hello = e.client.start(nonce)                     # victim reuses the burned challenge
    victim_failed, _ = _rejects(lambda: e.server.handle_client_hello(victim_hello), HandshakeError)
    retry = e.fresh_client()
    try:
        run_handshake(retry, e.server)
        retry_ok = True
    except HandshakeError:
        retry_ok = False
    passed = attacker_rejected and victim_failed and retry_ok
    return passed, "attacker not authenticated; one handshake wasted, retry succeeds (DoS only)"


SCENARIOS = [
    ("Replay", "Replay a captured ClientHello", s_replay_hello, "Rejected"),
    ("Replay", "Replay a captured encrypted record", s_replay_record, "Rejected"),
    ("Replay", "Use an expired challenge", s_stale_challenge, "Rejected"),
    ("Replay", "Use a challenge the server never issued", s_forged_challenge, "Rejected"),
    ("Impersonation", "Attacker signs with own key as a real device", s_impersonation_wrong_key, "Rejected"),
    ("Impersonation", "Unregistered device tries to log in", s_unregistered_device, "Rejected"),
    ("Impersonation", "Revoked device tries to log in", s_revoked_device, "Rejected"),
    ("MITM", "Swap the client's ephemeral key in transit", s_mitm_client_key_swap, "Rejected"),
    ("MITM", "Swap the server's ephemeral key in transit", s_mitm_server_key_swap, "Rejected"),
    ("MITM", "Rogue server with a different key", s_rogue_server, "Rejected"),
    ("Integrity", "Flip one bit of a ciphertext", s_tampered_ciphertext, "Rejected"),
    ("Integrity", "Reuse a client signature as a server signature", s_cross_role_signature, "Rejected"),
    ("Forward secrecy", "Steal both long-term keys after the session", s_forward_secrecy, "Old data safe"),
    ("Denial of service", "Burn an observed challenge", s_challenge_burn, "No auth, DoS only"),
]


def run_attacks() -> list[dict]:
    results = []
    for i, (category, name, fn, expected) in enumerate(SCENARIOS, start=1):
        passed, observed = fn()
        results.append({
            "id": i, "category": category, "name": name,
            "expected": expected, "observed": observed, "passed": bool(passed),
        })
    return results


# ---------------------------------------------------------------------------
# Performance: ECC P-256 vs RSA-2048 vs RSA-3072
# ---------------------------------------------------------------------------

def _median_ms(fn, runs: int) -> float:
    samples = []
    for _ in range(runs):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1000.0)
    return statistics.median(samples)


def _der_pub(pub) -> bytes:
    return pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _der_priv(priv) -> bytes:
    return priv.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption())


def bench_ecc(runs: int = 200) -> dict:
    priv = keys.generate_keypair()
    pub = priv.public_key()
    msg = b"benchmark message" * 4
    sig = keys.sign(priv, msg)
    sig_sizes = [len(keys.sign(priv, msg)) for _ in range(50)]
    peer = keys.generate_keypair().public_key()
    return {
        "keygen_ms": _median_ms(keys.generate_keypair, runs),
        "sign_ms": _median_ms(lambda: keys.sign(priv, msg), runs),
        "verify_ms": _median_ms(lambda: keys.verify(pub, sig, msg), runs),
        "ecdh_ms": _median_ms(lambda: priv.exchange(ec.ECDH(), peer), runs),
        "public_key_bytes": len(_der_pub(pub)),
        "public_point_bytes": len(keys.public_bytes(pub)),
        "private_key_bytes": len(_der_priv(priv)),
        "signature_bytes": round(statistics.mean(sig_sizes), 1),
        "signature_bytes_max": max(sig_sizes),
    }


def bench_rsa(bits: int, keygen_runs: int, runs: int) -> dict:
    gen = lambda: rsa.generate_private_key(public_exponent=65537, key_size=bits)
    priv = gen()
    pub = priv.public_key()
    msg = b"benchmark message" * 4
    pad = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH)
    sig = priv.sign(msg, pad, hashes.SHA256())
    return {
        "keygen_ms": _median_ms(gen, keygen_runs),
        "sign_ms": _median_ms(lambda: priv.sign(msg, pad, hashes.SHA256()), runs),
        "verify_ms": _median_ms(lambda: pub.verify(sig, msg, pad, hashes.SHA256()), runs),
        "public_key_bytes": len(_der_pub(pub)),
        "private_key_bytes": len(_der_priv(priv)),
        "signature_bytes": len(sig),
    }


def bench_handshake(runs: int = 50) -> float:
    e = Env()
    def one():
        run_handshake(e.fresh_client(), e.server)
    return _median_ms(one, runs)


def run_benchmarks(quick: bool = False) -> dict:
    ecc = bench_ecc(60 if quick else 200)
    # RSA key generation searches for random primes, so its time varies a lot
    # between runs: use many samples for a stable median.
    rsa2048 = bench_rsa(2048, 5 if quick else 40, 50 if quick else 150)
    rsa3072 = bench_rsa(3072, 3 if quick else 20, 30 if quick else 100)
    handshake_ms = bench_handshake(15 if quick else 50)
    ratios = {
        "keygen_rsa2048_over_ecc": rsa2048["keygen_ms"] / ecc["keygen_ms"],
        "keygen_rsa3072_over_ecc": rsa3072["keygen_ms"] / ecc["keygen_ms"],
        "sign_rsa2048_over_ecc": rsa2048["sign_ms"] / ecc["sign_ms"],
        "verify_ecc_over_rsa2048": ecc["verify_ms"] / rsa2048["verify_ms"],
        "pubkey_rsa2048_over_ecc": rsa2048["public_key_bytes"] / ecc["public_key_bytes"],
        "signature_rsa2048_over_ecc": rsa2048["signature_bytes"] / ecc["signature_bytes"],
    }
    return {"ecc_p256": ecc, "rsa_2048": rsa2048, "rsa_3072": rsa3072,
            "handshake_ms": handshake_ms, "ratios": ratios}
