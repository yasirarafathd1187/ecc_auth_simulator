import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ecc_sim import analysis, keys
from ecc_sim.handshake import Client, HandshakeError, Server, SessionError, run_handshake
from ecc_sim.registry import Registry, RegistryError, enroll, proof_message


class RegistryTests(unittest.TestCase):
    def test_register_then_reject_duplicates(self):
        reg = Registry()
        _, rec = enroll(reg, "alice", "dev-1")
        self.assertEqual(rec["status"], "active")
        with self.assertRaises(RegistryError):
            enroll(reg, "bob", "dev-1")                      # duplicate device ID
        priv = keys.generate_keypair()
        enroll(reg, "bob", "dev-2", private_key=priv)
        with self.assertRaises(RegistryError):
            enroll(reg, "carol", "dev-3", private_key=priv)  # duplicate public key

    def test_proof_of_possession_required(self):
        reg = Registry()
        victim_pub = keys.generate_keypair().public_key()
        attacker = keys.generate_keypair()
        nonce = reg.new_registration_challenge()
        bad_proof = keys.sign(attacker, proof_message("dev-1", nonce))
        with self.assertRaises(RegistryError):
            reg.register("mallory", "dev-1", "password-1", victim_pub, nonce, bad_proof)

    def test_password_is_salted_hash(self):
        reg = Registry()
        enroll(reg, "alice", "dev-1", "my-password-1")
        enroll(reg, "bob", "dev-2", "my-password-1")
        rows = reg.db.execute("SELECT pw_salt, pw_hash FROM devices").fetchall()
        self.assertNotEqual(rows[0][0], rows[1][0])          # different salts
        self.assertNotEqual(rows[0][1], rows[1][1])          # so different hashes
        self.assertTrue(reg.verify_password("dev-1", "my-password-1"))
        self.assertFalse(reg.verify_password("dev-1", "wrong-password"))


class KeyTests(unittest.TestCase):
    def test_pem_round_trip_and_sign_verify(self):
        priv = keys.generate_keypair()
        pem = keys.export_private_pem(priv, b"pw")
        self.assertIn(b"ENCRYPTED", pem)
        again = keys.import_private_pem(pem, b"pw")
        self.assertEqual(keys.fingerprint(priv.public_key()), keys.fingerprint(again.public_key()))
        with self.assertRaises(keys.KeyError_):
            keys.import_private_pem(pem, b"wrong")
        sig = keys.sign(priv, b"hello")
        self.assertTrue(keys.verify(priv.public_key(), sig, b"hello"))
        self.assertFalse(keys.verify(priv.public_key(), sig, b"hellO"))


class HandshakeTests(unittest.TestCase):
    def test_keys_match_and_records_work(self):
        e = analysis.Env()
        cs, ss = run_handshake(e.client, e.server)
        self.assertEqual(cs.send_key, ss.recv_key)
        self.assertEqual(cs.recv_key, ss.send_key)
        ctr, ct = cs.seal(b"hello")
        self.assertEqual(ss.open(ctr, ct), b"hello")
        ctr2, ct2 = ss.seal(b"reply")
        self.assertEqual(cs.open(ctr2, ct2), b"reply")

    def test_replay_is_rejected(self):
        e = analysis.Env()
        hello = e.client.start(e.server.new_challenge())
        e.server.handle_client_hello(hello)
        with self.assertRaises(HandshakeError):
            e.server.handle_client_hello(hello)


class AttackTests(unittest.TestCase):
    def test_all_14_scenarios_behave_as_expected(self):
        results = analysis.run_attacks()
        self.assertEqual(len(results), 14)
        failed = [r["name"] for r in results if not r["passed"]]
        self.assertEqual(failed, [])



class HardeningTests(unittest.TestCase):
    def test_registry_connection_can_be_used_from_another_thread(self):
        import threading
        reg = Registry()
        errors = []
        thread = threading.Thread(target=lambda: self._thread_lookup(reg, errors))
        thread.start()
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive(), "database lookup thread did not finish")
        self.assertEqual(errors, [])

    @staticmethod
    def _thread_lookup(reg, errors):
        try:
            reg.events()
        except Exception as exc:
            errors.append(exc)

    def test_rotation_rejects_another_devices_public_key(self):
        reg = Registry()
        _, first = enroll(reg, "alice", "dev-a")
        second_key, _ = enroll(reg, "bob", "dev-b")
        nonce = reg.new_registration_challenge()
        proof = keys.sign(second_key, proof_message("dev-a", nonce))
        with self.assertRaises(RegistryError):
            reg.rotate("dev-a", "correct-horse-1", second_key.public_key(), nonce, proof)
        self.assertEqual(reg.get_device("dev-a")["fingerprint"], first["fingerprint"])

    def test_invalid_record_counters_are_rejected_cleanly(self):
        e = analysis.Env()
        client, server = run_handshake(e.client, e.server)
        with self.assertRaises(SessionError):
            server.open(-1, b"not-a-record")
        with self.assertRaises(SessionError):
            server.open(2**96, b"not-a-record")
        counter, ciphertext = client.seal(b"valid")
        self.assertEqual(server.open(counter, ciphertext), b"valid")

    def test_failed_authentication_does_not_consume_receive_counter(self):
        e = analysis.Env()
        client, server = run_handshake(e.client, e.server)
        counter, ciphertext = client.seal(b"message")
        tampered = bytearray(ciphertext)
        tampered[-1] ^= 1
        with self.assertRaises(SessionError):
            server.open(counter, bytes(tampered))
        self.assertEqual(server.open(counter, ciphertext), b"message")

    def test_password_hashes_are_not_plaintext(self):
        reg = Registry()
        enroll(reg, "alice", "dev-password", "a-strong-password")
        row = reg.db.execute("SELECT pw_hash FROM devices WHERE device_id=?", ("dev-password",)).fetchone()
        self.assertNotEqual(row[0], b"a-strong-password")
        self.assertFalse(reg.verify_password("missing", "a-strong-password"))

if __name__ == "__main__":
    unittest.main()
