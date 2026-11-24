# ECC-Based Secure Authentication and Key Exchange Simulator

A Streamlit web application for demonstrating ECC-based device registration, mutual authentication, key exchange, authenticated encryption, security tests and performance comparisons.

**Course:** CSA5111 – Cryptography and Network Security  
**Stack:** Python · Streamlit · SQLite · cryptography · pandas

## Run locally

Python 3.10 or newer is recommended.

```bash
git clone https://github.com/yasirarafathd1187/ecc_auth_simulator.git
cd ecc_auth_simulator
pip install -r requirements.txt
streamlit run ecc_auth_simulator/app.py
```

## Deploy on Streamlit Community Cloud

1. Sign in to Streamlit Community Cloud and connect your GitHub account.
2. Select this repository and the `feature/streamlit-dashboard` branch (or `main` after merging the changes).
3. Set **Main file path** to `ecc_auth_simulator/app.py`.
4. Deploy. The root-level `requirements.txt` installs the dependencies.

## Website pages

- **Overview:** Project summary, module descriptions, device metrics and event log.
- **Device Registration:** Enroll devices using a generated P-256 key pair, proof of possession and salted scrypt password hash. Revoke active demo devices.
- **Key Management:** Inspect public-key fingerprints and PEM data; sign and verify messages with ECDSA.
- **Secure Authentication:** Run the mutual-authentication handshake, derive session keys with ECDH/HKDF, and encrypt/decrypt a sample message with AES-256-GCM.
- **Security Tests:** Run the 14 defensive scenarios defined in `ecc_sim/analysis.py`.
- **Performance:** Run a quick ECC P-256 vs RSA-2048/RSA-3072 benchmark and view charts.
- **About:** Algorithms, architecture and limitations.

## Cryptographic protocol

1. Server issues a fresh single-use challenge.
2. Client signs its identity, nonces and ephemeral public key using ECDSA.
3. Server verifies the client and signs its own ephemeral public key.
4. Both endpoints derive matching session keys using ECDH and HKDF-SHA256.
5. AES-256-GCM protects application records with authenticated encryption.

## Existing Python modules

| Module | File | Purpose |
|---|---|---|
| 1 – Registration | `ecc_auth_simulator/ecc_sim/registry.py` | SQLite registry, scrypt password hashes, proof of possession, revoke and rotate |
| 2 – Key management | `ecc_auth_simulator/ecc_sim/keys.py` | P-256 keys, SHA-256 fingerprints, encrypted PEM export/import, ECDSA |
| 3 – Authentication | `ecc_auth_simulator/ecc_sim/handshake.py` | Mutual signatures, ephemeral ECDH, HKDF-SHA256, AES-256-GCM and replay protection |
| 4 – Analysis | `ecc_auth_simulator/ecc_sim/analysis.py` | 14 security scenarios and ECC/RSA performance benchmarks |

## Run the original command-line demonstration

```bash
cd ecc_auth_simulator
python run_demo.py --quick
python -m unittest discover -s tests -v
```

## Important limitations

- This is an educational simulator. Client and server run in one Python process; it is not a real network service.
- The server public key is pinned in the client. The simulator does not implement a certificate authority or certificate-chain validation.
- The Streamlit demo registry and device keys are kept in session memory and reset when the session restarts. Do not enter real passwords or production secrets.
- Benchmark values depend on the machine and runtime. They are not universal performance guarantees.
- The challenge-consumption scenario demonstrates a denial-of-service limitation; a passing test means the observed behaviour matches the scenario's expected result.
