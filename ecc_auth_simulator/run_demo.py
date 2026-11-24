"""Run the whole simulator end to end and write results/ (JSON, PNG charts, log).

    python run_demo.py            # full run (about a minute because RSA key generation is slow)
    python run_demo.py --quick    # fewer repetitions, rougher timings
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from ecc_sim import analysis, keys
from ecc_sim.handshake import Client, Server, derive_keys, run_handshake, server_message
from ecc_sim.registry import Registry, RegistryError, enroll

HERE = Path(__file__).resolve().parent
OUT = HERE / "results"


class Tee:
    """Print to the console and keep a copy for results/demo_output.txt."""

    def __init__(self):
        self.lines: list[str] = []

    def __call__(self, text: str = "") -> None:
        print(text)
        self.lines.append(text)


def hexs(b: bytes, n: int = 16) -> str:
    h = b.hex()
    return h if len(h) <= n * 2 else h[: n * 2] + "..."


def demo_protocol(say: Tee) -> dict:
    """Module 1-3 walkthrough.  Returns a few real values for the slides."""
    say("=== Module 1: registration ===")
    clock_registry = Registry(":memory:")
    server_key = keys.generate_keypair()
    server = Server(clock_registry, server_key)
    device_key, rec = enroll(clock_registry, "alice", "sensor-01", "s3cret-pass")
    say(f"registered device_id={rec['device_id']} user={rec['user_id']} status={rec['status']}")
    say(f"public-key fingerprint (SHA-256): {rec['fingerprint'][:32]}...")
    try:
        enroll(clock_registry, "mallory", "sensor-01", "another-pass1")
    except RegistryError as exc:
        say(f"duplicate registration rejected: {exc}")
    say(f"password check (right): {clock_registry.verify_password('sensor-01', 's3cret-pass')}")
    say(f"password check (wrong): {clock_registry.verify_password('sensor-01', 'guess-guess')}")

    say("")
    say("=== Module 2: key management ===")
    say(f"curve: {keys.CURVE_NAME}")
    say(f"fingerprint (short): {keys.short_fingerprint(device_key.public_key())}")
    pem = keys.export_private_pem(device_key, b"export-pass")
    say(f"private key exported to encrypted PEM ({len(pem)} bytes), first line: {pem.splitlines()[0].decode()}")
    again = keys.import_private_pem(pem, b"export-pass")
    say(f"re-imported key matches: {keys.fingerprint(again.public_key()) == rec['fingerprint']}")
    try:
        keys.import_private_pem(pem, b"wrong")
    except keys.KeyError_:
        say("import with wrong password rejected")

    say("")
    say("=== Module 3: handshake ===")
    client = Client("sensor-01", device_key, server.public_key)
    nonce_s = server.new_challenge()
    hello = client.start(nonce_s)
    server_hello, srv_session = server.handle_client_hello(hello)
    cli_session = client.finish(server_hello)
    say(f"server nonce      : {hexs(hello.nonce_s)}")
    say(f"client nonce      : {hexs(hello.nonce_c)}")
    say(f"client ephemeral  : {hexs(hello.eph_c, 20)}")
    say(f"server ephemeral  : {hexs(server_hello.eph_s, 20)}")
    say(f"client ECDSA sig  : {hexs(hello.signature, 20)}  ({len(hello.signature)} bytes)")
    say(f"session id        : {srv_session.session_id.hex()}")
    say(f"keys match        : {cli_session.send_key == srv_session.recv_key and cli_session.recv_key == srv_session.send_key}")
    ctr, ct = cli_session.seal(b"temperature=21.5C")
    say(f"AES-256-GCM record: counter={ctr} ciphertext={hexs(ct, 16)}")
    say(f"server decrypts   : {srv_session.open(ctr, ct).decode()}")

    clock_registry.revoke("sensor-01", "demo revoke")
    new_key = keys.generate_keypair()
    say(f"event log entries : {len(clock_registry.events())}")
    return {
        "fingerprint": rec["fingerprint"],
        "server_nonce": hello.nonce_s.hex(),
        "client_eph": hello.eph_c.hex(),
        "server_eph": server_hello.eph_s.hex(),
        "signature": hello.signature.hex(),
        "session_id": srv_session.session_id.hex(),
        "record_ciphertext": ct.hex(),
    }


def make_charts(bench: dict) -> None:
    ecc, r2, r3 = bench["ecc_p256"], bench["rsa_2048"], bench["rsa_3072"]
    colors = ["#0F766E", "#B45309", "#7C2D12"]
    labels = ["ECC P-256", "RSA-2048", "RSA-3072"]

    fig, axes = plt.subplots(1, 3, figsize=(11, 3.8))
    for ax, key, title in zip(axes, ["keygen_ms", "sign_ms", "verify_ms"],
                              ["Key generation", "Signing", "Verification"]):
        vals = [ecc[key], r2[key], r3[key]]
        bars = ax.bar(labels, vals, color=colors)
        ax.set_yscale("log")
        ax.set_ylim(bottom=min(vals) / 10, top=max(vals) * 3)  # honest baseline on a log axis
        ax.set_title(title)
        ax.set_ylabel("median time (ms, log scale)")
        for b, v in zip(bars, vals):
            ax.text(b.get_x() + b.get_width() / 2, v, f"{v:.3g}", ha="center", va="bottom", fontsize=9)
        ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(OUT / "timing.png", dpi=160)
    plt.close(fig)

    fig, axes = plt.subplots(1, 2, figsize=(9, 3.6))
    for ax, key, title in zip(axes, ["public_key_bytes", "signature_bytes"],
                              ["Public key (DER)", "Signature"]):
        vals = [ecc[key], r2[key], r3[key]]
        bars = ax.bar(labels, vals, color=colors)
        ax.set_title(title)
        ax.set_ylabel("bytes")
        for b, v in zip(bars, vals):
            ax.text(b.get_x() + b.get_width() / 2, v, f"{v:g}", ha="center", va="bottom", fontsize=9)
        ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(OUT / "sizes.png", dpi=160)
    plt.close(fig)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true", help="fewer benchmark repetitions")
    args = ap.parse_args()
    OUT.mkdir(exist_ok=True)
    say = Tee()

    values = demo_protocol(say)

    say("")
    say("=== Module 4: attack scenarios ===")
    attacks = analysis.run_attacks()
    for a in attacks:
        mark = "PASS" if a["passed"] else "FAIL"
        say(f"[{mark}] {a['id']:>2}. {a['category']:<18} {a['name']}")
    passed = sum(a["passed"] for a in attacks)
    say(f"{passed}/{len(attacks)} scenarios behaved as expected")

    say("")
    say("=== Module 4: ECC P-256 vs RSA (this may take a minute) ===")
    bench = analysis.run_benchmarks(quick=args.quick)
    e, r2, r3 = bench["ecc_p256"], bench["rsa_2048"], bench["rsa_3072"]
    say(f"{'':<14}{'ECC P-256':>12}{'RSA-2048':>12}{'RSA-3072':>12}")
    for key, label in [("keygen_ms", "keygen ms"), ("sign_ms", "sign ms"), ("verify_ms", "verify ms")]:
        say(f"{label:<14}{e[key]:>12.4f}{r2[key]:>12.4f}{r3[key]:>12.4f}")
    for key, label in [("public_key_bytes", "pubkey bytes"), ("signature_bytes", "sig bytes")]:
        say(f"{label:<14}{e[key]:>12g}{r2[key]:>12g}{r3[key]:>12g}")
    say(f"full handshake (median): {bench['handshake_ms']:.3f} ms")
    r = bench["ratios"]
    say(f"keygen: RSA-2048 is {r['keygen_rsa2048_over_ecc']:.0f}x slower than ECC")
    say(f"verify: ECDSA is {r['verify_ecc_over_rsa2048']:.1f}x slower than RSA-2048 (RSA verify is cheap)")

    make_charts(bench)
    results = {
        "environment": {"python": platform.python_version(), "os": platform.platform(),
                        "quick_mode": args.quick},
        "values_from_run": values,
        "attacks": attacks,
        "attacks_passed": passed,
        "attacks_total": len(attacks),
        "benchmark": bench,
    }
    (OUT / "results.json").write_text(json.dumps(results, indent=2))
    (OUT / "demo_output.txt").write_text("\n".join(say.lines) + "\n")
    say("")
    say(f"wrote {OUT / 'results.json'}, timing.png, sizes.png, demo_output.txt")
    return 0 if passed == len(attacks) else 1


if __name__ == "__main__":
    sys.exit(main())
