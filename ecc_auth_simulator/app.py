from __future__ import annotations

import io
import sys
import unittest
from pathlib import Path

import pandas as pd
import streamlit as st

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from ecc_sim import analysis, keys
from ecc_sim.handshake import Client, Server, SessionError, run_handshake
from ecc_sim.registry import Registry, RegistryError, enroll

st.set_page_config(
    page_title="ECC Auth Simulator",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
  .stApp { background: #0b1220; }
  [data-testid="stSidebar"] { background: #101a2c; border-right: 1px solid #24334a; }
  [data-testid="stMetric"] { background: #111d30; border: 1px solid #263852; padding: 16px; border-radius: 12px; }
  div[data-testid="stForm"] { background: #111d30; border: 1px solid #263852; padding: 18px; border-radius: 12px; }
  .hero { padding: 28px; border: 1px solid #263852; border-radius: 18px; background: linear-gradient(120deg,#12233c,#111827); margin-bottom: 18px; }
  .muted { color: #9fb0c8; }
  .pill { display:inline-block; padding:4px 10px; border-radius:20px; background:#173b36; color:#80e0c0; font-size:12px; }
</style>
""", unsafe_allow_html=True)


def init_demo() -> None:
    if "registry" not in st.session_state:
        registry = Registry(":memory:")
        server_key = keys.generate_keypair()
        server = Server(registry, server_key)
        private_key, record = enroll(
            registry, "demo-user", "sensor-01", "demo-password-123"
        )
        st.session_state.registry = registry
        st.session_state.server = server
        st.session_state.server_key = server_key
        st.session_state.device_keys = {"sensor-01": private_key}
        st.session_state.last_auth = None
        st.session_state.last_benchmark = None
        st.session_state.seed_record = record


def active_devices():
    registry = st.session_state.registry
    rows = []
    for device_id in st.session_state.device_keys:
        rec = registry.get_device(device_id)
        if rec:
            rows.append(rec)
    return rows


def page_header(title: str, subtitle: str) -> None:
    st.markdown(f'<div class="hero"><h1 style="margin:0">{title}</h1><p class="muted" style="margin:8px 0 0">{subtitle}</p></div>', unsafe_allow_html=True)


init_demo()
registry = st.session_state.registry
server = st.session_state.server
device_keys = st.session_state.device_keys

with st.sidebar:
    st.markdown("## 🔐 ECC AUTH")
    st.caption("Secure authentication simulator")
    page = st.radio(
        "NAVIGATION",
        ["Overview", "Device Registration", "Key Management", "Secure Authentication", "Security Tests", "Performance", "About"],
        label_visibility="collapsed",
    )
    st.divider()
    st.markdown('<span class="pill">LOCAL DEMO MODE</span>', unsafe_allow_html=True)
    st.caption("Data and keys live only in this browser session.")
    st.caption("NIST P-256 · ECDSA · ECDH · HKDF · AES-GCM")


if page == "Overview":
    page_header("ECC Secure Authentication", "An interactive, educational simulator for device identity, key exchange and protected messaging.")
    records = active_devices()
    events = registry.events()
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Registered devices", len(records))
    c2.metric("Active devices", sum(r["status"] == "active" for r in records))
    c3.metric("Security scenarios", "14")
    c4.metric("Elliptic curve", "P-256")
    st.subheader("How the system works")
    cols = st.columns(4)
    modules = [
        ("01", "Registration", "Device identity, salted scrypt password hashes and proof of private-key ownership."),
        ("02", "Key management", "P-256 key pairs, SHA-256 public-key fingerprints and ECDSA signatures."),
        ("03", "Authentication", "Mutual signatures, ephemeral ECDH, HKDF-SHA256 and AES-256-GCM."),
        ("04", "Security analysis", "Replay, impersonation, key-substitution and integrity test scenarios."),
    ]
    for col, (number, title, body) in zip(cols, modules):
        with col:
            st.markdown(f"### {number} · {title}")
            st.write(body)
    st.subheader("Recent security events")
    if events:
        st.dataframe(pd.DataFrame(events, columns=["ID", "Event", "Device", "Details"]), use_container_width=True, hide_index=True)
    else:
        st.info("No events recorded yet.")
    st.info("Start with Device Registration, then open Secure Authentication to exchange a session key and send an encrypted message.")


elif page == "Device Registration":
    page_header("Device Registration", "Enroll a device and prove possession of its ECC private key.")
    left, right = st.columns([1, 1])
    with left:
        st.subheader("Register a new device")
        with st.form("register_device"):
            user_id = st.text_input("User ID", placeholder="e.g. lab-user")
            device_id = st.text_input("Device ID", placeholder="e.g. temperature-node-02")
            password = st.text_input("Device password", type="password", help="At least 8 characters. This demo stores only a salted scrypt hash.")
            submitted = st.form_submit_button("Generate keys and register", use_container_width=True)
        if submitted:
            try:
                if device_id in device_keys:
                    raise RegistryError("That device ID already exists in this demo.")
                private_key, record = enroll(registry, user_id.strip(), device_id.strip(), password)
                device_keys[device_id.strip()] = private_key
                st.success(f"Device {device_id.strip()} registered successfully.")
                st.code(record["fingerprint"], language="text")
            except Exception as exc:
                st.error(str(exc))
    with right:
        st.subheader("Device inventory")
        records = active_devices()
        if records:
            view = [{
                "Device ID": r["device_id"],
                "User": r["user_id"],
                "Status": r["status"],
                "Key version": r["key_version"],
                "Fingerprint": r["fingerprint"][:16] + "…",
            } for r in records]
            st.dataframe(pd.DataFrame(view), use_container_width=True, hide_index=True)
        else:
            st.info("No devices are registered.")
        choices = [r["device_id"] for r in records if r["status"] == "active"]
        if choices:
            selected = st.selectbox("Select active device to revoke", choices)
            reason = st.text_input("Revocation reason", value="Revoked from demo dashboard")
            if st.button("Revoke selected device", type="secondary"):
                try:
                    registry.revoke(selected, reason)
                    st.warning(f"{selected} has been revoked.")
                    st.rerun()
                except RegistryError as exc:
                    st.error(str(exc))
    st.caption("The registry is in-memory for this demonstration. Restarting the app resets demo devices and event history.")


elif page == "Key Management":
    page_header("ECC Key Management", "Inspect public-key metadata and demonstrate ECDSA signing and verification.")
    records = active_devices()
    if not records:
        st.warning("Register a device first.")
    else:
        selected = st.selectbox("Choose a device", [r["device_id"] for r in records])
        rec = registry.get_device(selected)
        private_key = device_keys[selected]
        public_key = private_key.public_key()
        a, b, c = st.columns(3)
        a.metric("Curve", "NIST P-256")
        b.metric("Key size", "256 bits")
        c.metric("Status", rec["status"].upper())
        st.markdown("**SHA-256 public-key fingerprint**")
        st.code(keys.fingerprint(public_key))
        st.markdown("**Public key (PEM)**")
        st.code(keys.public_pem(public_key).decode(), language="text")
        st.divider()
        st.subheader("ECDSA signature playground")
        message = st.text_area("Message to sign", "Authenticate device sensor-01", height=90)
        if st.button("Sign message and verify", type="primary"):
            signature = keys.sign(private_key, message.encode("utf-8"))
            verified = keys.verify(public_key, signature, message.encode("utf-8"))
            st.session_state.signature_demo = {
                "message": message, "signature": signature.hex(), "verified": verified
            }
        result = st.session_state.get("signature_demo")
        if result:
            st.success("Signature verified successfully." if result["verified"] else "Signature verification failed.")
            st.caption("DER-encoded ECDSA signature (hex)")
            st.code(result["signature"])
            altered = result["message"] + " [modified]"
            st.write("Tamper check: verify the same signature against a modified message.")
            if st.button("Verify modified message"):
                tampered_ok = keys.verify(public_key, bytes.fromhex(result["signature"]), altered.encode("utf-8"))
                st.error("Unexpectedly verified." if tampered_ok else "Correctly rejected: message was changed.")


elif page == "Secure Authentication":
    page_header("Secure Authentication & Key Exchange", "Run the complete client–server handshake and protect a message with AES-256-GCM.")
    records = [r for r in active_devices() if r["status"] == "active"]
    if not records:
        st.warning("No active device is available. Register a device or revoke status is not reversible in this demo.")
    else:
        selected = st.selectbox("Client device", [r["device_id"] for r in records])
        message = st.text_area("Plaintext message", "temperature=21.5C", height=90)
        if st.button("Run mutual authentication", type="primary", use_container_width=True):
            try:
                client = Client(selected, device_keys[selected], server.public_key)
                client_session, server_session = run_handshake(client, server)
                counter, ciphertext = client_session.seal(message.encode("utf-8"))
                tampered = bytearray(ciphertext)
                tampered[-1] ^= 1
                try:
                    server_session.open(counter, bytes(tampered))
                    tamper_rejected = False
                except SessionError:
                    tamper_rejected = True
                plaintext = server_session.open(counter, ciphertext)
                reply = f"ACK: received {len(plaintext)} bytes"
                reply_counter, reply_ciphertext = server_session.seal(reply.encode("utf-8"))
                client_reply = client_session.open(reply_counter, reply_ciphertext)
                st.session_state.last_auth = {
                    "device": selected,
                    "session_id": client_session.session_id.hex(),
                    "keys_match": (
                        client_session.send_key == server_session.recv_key
                        and client_session.recv_key == server_session.send_key
                    ),
                    "counter": counter,
                    "ciphertext": ciphertext.hex(),
                    "plaintext": plaintext.decode("utf-8"),
                    "reply": client_reply.decode("utf-8"),
                    "tamper_rejected": tamper_rejected,
                }
            except Exception as exc:
                st.error(f"Authentication failed: {exc}")
        result = st.session_state.last_auth
        if result:
            st.divider()
            st.success("Mutual authentication completed. The server decrypted the protected message.")
            c1, c2, c3 = st.columns(3)
            c1.metric("Authentication", "VERIFIED")
            c2.metric("Session keys", "MATCH" if result["keys_match"] else "MISMATCH")
            c3.metric("Record counter", result["counter"])
            st.markdown("**Session ID**")
            st.code(result["session_id"])
            st.markdown("**AES-256-GCM ciphertext (hex)**")
            st.code(result["ciphertext"])
            st.markdown("**Server-decrypted plaintext**")
            st.code(result["plaintext"])
            st.markdown("**Encrypted server response received by client**")
            st.code(result["reply"])
            st.metric("Tampered ciphertext rejected", "YES" if result["tamper_rejected"] else "NO")
            st.caption("Both directions use independent AES-GCM keys and counters. The tamper probe is rejected before the valid record is accepted.")
            st.caption("This is an interactive protocol simulation inside one Streamlit process, not a deployed client/server network service.")
        with st.expander("What happens during the handshake?"):
            st.markdown("""
            1. The server issues a fresh, single-use challenge.
            2. The device signs its identity, both nonces and ephemeral public key with ECDSA.
            3. The server validates the device and signs its own ephemeral public key.
            4. Both sides derive matching session keys with ECDH and HKDF-SHA256.
            5. AES-256-GCM encrypts the application message and authenticates its contents.
            """)


elif page == "Security Tests":
    page_header("Security Test Lab", "Run adversarial protocol simulations and the complete automated regression suite.")
    st.warning("These are controlled, local demonstrations of defensive security properties—not tests against real systems.")
    test_col, attack_col = st.columns(2)
    with attack_col:
        if st.button("Run all 14 attack simulations", type="primary", use_container_width=True):
            with st.spinner("Running isolated attack scenarios…"):
                st.session_state.attack_results = analysis.run_attacks()
    with test_col:
        if st.button("Run full Python regression suite", use_container_width=True):
            output = io.StringIO()
            suite = unittest.defaultTestLoader.discover(str(HERE / "tests"), pattern="test_*.py")
            result = unittest.TextTestRunner(stream=output, verbosity=2).run(suite)
            st.session_state.unit_test_result = {
                "tests_run": result.testsRun,
                "failures": len(result.failures),
                "errors": len(result.errors),
                "successful": result.wasSuccessful(),
                "output": output.getvalue(),
            }
    unit = st.session_state.get("unit_test_result")
    if unit:
        a, b, c = st.columns(3)
        a.metric("Python tests", unit["tests_run"])
        b.metric("Failures + errors", unit["failures"] + unit["errors"])
        c.metric("Suite", "PASS" if unit["successful"] else "FAIL")
        with st.expander("Full test output", expanded=not unit["successful"]):
            st.code(unit["output"])
    results = st.session_state.get("attack_results")
    if results:
        passed = sum(bool(item["passed"]) for item in results)
        total = len(results)
        a, b, c = st.columns(3)
        a.metric("Expected behaviours", f"{passed}/{total}")
        b.metric("Unexpected results", total - passed)
        c.metric("Pass rate", f"{(passed / total * 100):.1f}%")
        table = [{
            "ID": item["id"],
            "Category": item["category"],
            "Scenario": item["name"],
            "Expected": item["expected"],
            "Observed": item["observed"],
            "Result": "PASS" if item["passed"] else "FAIL",
        } for item in results]
        st.dataframe(pd.DataFrame(table), use_container_width=True, hide_index=True)
        if passed == total:
            st.success("All scenarios behaved as expected.")
        else:
            st.error("One or more scenarios did not behave as expected. Review the observed results.")
        st.caption("A PASS means the defensive behaviour matched the test's expectation. Scenario 14 demonstrates a limited challenge-consumption denial-of-service condition.")
    else:
        st.info("Click the button to run the scenarios. Each scenario creates its own fresh test environment.")


elif page == "Performance":
    page_header("Performance & Size Comparison", "Compare ECC P-256 with RSA-2048 and RSA-3072 on this app's runtime.")
    st.info("Benchmark values depend on the machine running Streamlit. Quick mode uses fewer repetitions and is intended for demonstration.")
    if st.button("Run quick benchmark", type="primary"):
        with st.spinner("Generating benchmark keys and measuring operations… this may take a little while."):
            try:
                st.session_state.last_benchmark = analysis.run_benchmarks(quick=True)
            except Exception as exc:
                st.error(f"Benchmark failed: {exc}")
    bench = st.session_state.get("last_benchmark")
    if bench:
        labels = ["ECC P-256", "RSA-2048", "RSA-3072"]
        groups = [
            ("Key generation (ms)", "keygen_ms"),
            ("Signing (ms)", "sign_ms"),
            ("Verification (ms)", "verify_ms"),
            ("Public key size (bytes)", "public_key_bytes"),
            ("Signature size (bytes)", "signature_bytes"),
        ]
        for title, key in groups:
            st.subheader(title)
            frame = pd.DataFrame({
                "Algorithm": labels,
                "Value": [bench["ecc_p256"][key], bench["rsa_2048"][key], bench["rsa_3072"][key]],
            }).set_index("Algorithm")
            st.bar_chart(frame)
            st.dataframe(frame, use_container_width=True)
        st.metric("Full handshake median", f'{bench["handshake_ms"]:.3f} ms')
        st.caption("Measurements are illustrative runtime observations, not universal performance guarantees.")
    else:
        st.info("Run the benchmark to generate comparison charts.")


else:
    page_header("About This Project", "ECC-Based Secure Authentication and Key Exchange Simulator")
    st.markdown("""
    **Course:** CSA5111 – Cryptography and Network Security

    **Goal:** Demonstrate how devices can prove their identity, establish shared session keys and exchange authenticated encrypted messages.

    | Component | Implementation |
    |---|---|
    | Elliptic curve | NIST P-256 / secp256r1 |
    | Device passwords | Salted scrypt hashes |
    | Digital signatures | ECDSA with SHA-256 |
    | Key agreement | Ephemeral ECDH |
    | Key derivation | HKDF-SHA256 |
    | Authenticated encryption | AES-256-GCM |
    | Registry | SQLite in-memory database |
    | Analysis | 14 defensive test scenarios and ECC/RSA benchmarks |

    **Important limitations:** Client and server execute in the same process; the server public key is pinned rather than validated through a certificate chain; and demo state is not persistent. This is an educational simulator, not a production authentication service.
    """)
    st.markdown("**Source code:** [GitHub – ecc_auth_simulator](https://github.com/yasirarafathd1187/ecc_auth_simulator)")
