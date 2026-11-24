# ECC-Based Secure Authentication and Key Exchange Simulator

CSA5111 - Cryptography and Network Security.
Python simulator for the project deck `ECC_Authentication_Key_Exchange_Revised.pptx`.

## Setup and run

```
pip install cryptography matplotlib
python run_demo.py            # full run, writes results/
python run_demo.py --quick    # fewer repetitions, rougher timings
python -m unittest discover -s tests -v
```

Needs Python 3.10 or newer. `run_demo.py` writes `results/results.json`,
`results/timing.png`, `results/sizes.png` and `results/demo_output.txt`.

## Modules (one file each)

| Module | File | What it does |
|---|---|---|
| 1 Registration | `ecc_sim/registry.py` | SQLite registry, salted scrypt password hashes, proof that the device holds its private key, duplicate rejection, revoke and rotate, event log |
| 2 Key management | `ecc_sim/keys.py` | P-256 keys, SHA-256 fingerprints, encrypted PEM export and import, ECDSA sign and verify |
| 3 Authentication | `ecc_sim/handshake.py` | Both sides sign their ephemeral keys, then ECDH, HKDF-SHA256 and AES-256-GCM, with replay protection |
| 4 Analysis | `ecc_sim/analysis.py` | 14 attack scenarios, plus ECC P-256 vs RSA-2048 and RSA-3072 timing and size |

## Protocol

```
Server -> Client : nonce_s
Client -> Server : device_id, nonce_s, nonce_c, eph_c, ECDSA_dev(CLIENT || fields)
Server -> Client : eph_s, ECDSA_srv(SERVER || fields)
both             : shared = ECDH(eph, peer_eph)
                   keys   = HKDF-SHA256(shared, salt = nonce_s || nonce_c, info = H(transcript))
data             : AES-256-GCM, one key per direction, strictly increasing record counter
```

* Each challenge is single-use and expires after 30 seconds.
* Client and server signatures carry different role labels (domain separation).
* Ephemeral private keys are dropped after the handshake (forward secrecy).

## Known limits

* Client and server run in one process. There is no real network.
* The server key is pinned in the client. There is no certificate chain.
* Challenges travel in the clear, so an observer can use one up and make a
  legitimate handshake fail once. That is a denial of service, not impersonation
  (attack scenario 14). The client retries with a fresh challenge.
* Password hashing is scrypt, because Argon2 is not in the `cryptography` package.
* Timings depend on the machine. Re-run `run_demo.py` on your own computer
  before presenting and update the deck from the new `results/results.json`.
