"""Module 2 - ECC key generation and management (curve NIST P-256).

Keys are generated with the `cryptography` library.  The private key stays
on the device; only the public key is ever shared.  Private keys can be
exported to password-encrypted PEM and imported again.
"""

from __future__ import annotations

import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

CURVE = ec.SECP256R1()
CURVE_NAME = "NIST P-256 (secp256r1)"


class KeyError_(Exception):
    """Raised for key import/export problems."""


def generate_keypair() -> ec.EllipticCurvePrivateKey:
    """Generate a fresh P-256 private key (the public key is derived from it)."""
    return ec.generate_private_key(CURVE)


# ---- public key encodings -------------------------------------------------

def public_bytes(pub: ec.EllipticCurvePublicKey) -> bytes:
    """Uncompressed X9.62 point: 0x04 || X || Y (65 bytes for P-256)."""
    return pub.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )


def public_from_bytes(data: bytes) -> ec.EllipticCurvePublicKey:
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(CURVE, data)
    except (ValueError, TypeError) as exc:
        raise KeyError_(f"invalid P-256 public point: {exc}") from exc


def public_der(pub: ec.EllipticCurvePublicKey) -> bytes:
    """SubjectPublicKeyInfo DER (91 bytes for P-256)."""
    return pub.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def public_pem(pub: ec.EllipticCurvePublicKey) -> bytes:
    return pub.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def public_from_pem(pem: bytes) -> ec.EllipticCurvePublicKey:
    try:
        key = serialization.load_pem_public_key(pem)
    except ValueError as exc:
        raise KeyError_(f"cannot parse public key PEM: {exc}") from exc
    _require_p256(key)
    return key


def _require_p256(key) -> None:
    if not isinstance(key, (ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey)):
        raise KeyError_("not an elliptic-curve key")
    if not isinstance(key.curve, ec.SECP256R1):
        raise KeyError_("key is not on curve P-256")


def fingerprint(pub: ec.EllipticCurvePublicKey) -> str:
    """SHA-256 of the DER public key, as lowercase hex."""
    return hashlib.sha256(public_der(pub)).hexdigest()


def short_fingerprint(pub: ec.EllipticCurvePublicKey) -> str:
    fp = fingerprint(pub)
    return ":".join(fp[i : i + 4] for i in range(0, 16, 4))


# ---- private key import / export -------------------------------------------

def export_private_pem(
    priv: ec.EllipticCurvePrivateKey, password: bytes | None
) -> bytes:
    """PKCS#8 PEM, encrypted with `password` (best available algorithm)."""
    if password:
        enc = serialization.BestAvailableEncryption(password)
    else:
        enc = serialization.NoEncryption()
    return priv.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc
    )


def import_private_pem(pem: bytes, password: bytes | None) -> ec.EllipticCurvePrivateKey:
    try:
        key = serialization.load_pem_private_key(pem, password=password or None)
    except (ValueError, TypeError) as exc:
        raise KeyError_(f"cannot load private key (wrong password?): {exc}") from exc
    _require_p256(key)
    return key


# ---- ECDSA -----------------------------------------------------------------

def sign(priv: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
    """ECDSA over SHA-256; returns a DER-encoded signature."""
    return priv.sign(data, ec.ECDSA(hashes.SHA256()))


def verify(pub: ec.EllipticCurvePublicKey, signature: bytes, data: bytes) -> bool:
    try:
        pub.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False
