import hashlib
import hmac
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from test_environment import configure
configure()
from vpn_env import env, port as env_port, expand
import verify_mtproto as probe


class MTProtoVerificationTests(unittest.TestCase):
    def test_openssl_aes256_ctr_matches_nist_vector_across_chunks(self):
        key = bytes.fromhex('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4')
        iv = bytes.fromhex('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff')
        plain = bytes.fromhex('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51')
        expected = bytes.fromhex('601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c5')
        aes = probe.AESCTR(key, iv)
        try:
            self.assertEqual(aes.crypt(plain[:7]) + aes.crypt(plain[7:]), expected)
        finally:
            aes.close()

    def test_generated_clienthello_has_secret_authenticated_random(self):
        key = bytes(range(16))
        hello, random, session = probe.client_hello(key, 'example.org')
        normalized = hello[:11] + bytes(32) + hello[43:]
        digest = hmac.digest(key, normalized, 'sha256')
        self.assertEqual(random[:28], digest[:28])
        self.assertIn(b'example.org', hello)
        self.assertGreater(len(session), 0)
        self.assertNotEqual(random[28:], digest[28:])

    def test_fake_tls_server_digest_must_match_secret_and_session(self):
        key, nonce, session = bytes(range(16)), bytes(range(32)), b'fixture'
        first = bytearray(b'\x16\x03\x03\x00\x00\x02\x00\x00\x00\x03\x03' + bytes(32)
                          + bytes([len(session)]) + session + bytes(8))
        first[3:5] = struct.pack('>H', len(first) - 5)
        ccs, noise = b'\x14\x03\x03\x00\x01\x01', b'\x17\x03\x03\x00\x04abcd'
        first[11:43] = hmac.digest(key, nonce + first + ccs + noise, 'sha256')
        probe.authenticate_server(key, nonce, session, [bytes(first), ccs, noise])
        with self.assertRaises(probe.ProbeError):
            probe.authenticate_server(b'x' * 16, nonce, session, [bytes(first), ccs, noise])
        with self.assertRaises(probe.ProbeError):
            probe.authenticate_server(key, nonce, b'wrong', [bytes(first), ccs, noise])

    def test_respq_rejects_wrong_nonce_and_malformed_lengths(self):
        nonce = bytes(range(16))
        body = struct.pack('<I', probe.RES_PQ) + nonce + b's' * 16 + b'\x02\x01\x03\0'
        body += struct.pack('<IIQ', probe.VECTOR, 1, 123)
        envelope = bytes(8) + struct.pack('<QI', 1, len(body)) + body
        self.assertEqual(probe.validate_res_pq(envelope, nonce), 1)
        with self.assertRaises(probe.ProbeError):
            probe.validate_res_pq(envelope, b'x' * 16)
        with self.assertRaises(probe.ProbeError):
            probe.validate_res_pq(envelope + b'x' * 16, nonce)

    def test_obfuscated_handshake_uses_secret_mixed_ciphers(self):
        key = bytes(range(16))
        frame, send, receive = probe.obfuscated_transport(key, 3)
        server_receive = probe.AESCTR(hashlib.sha256(frame[8:40] + key).digest(), frame[40:56])
        try:
            decoded = server_receive.crypt(frame)
            self.assertEqual(decoded[56:60], b'\xdd' * 4)
            self.assertEqual(struct.unpack('<h', decoded[60:62])[0], 3)
            request = b'stream-position-must-follow-64-byte-handshake'
            self.assertEqual(server_receive.crypt(send.crypt(request)), request)
        finally:
            send.close()
            receive.close()
            server_receive.close()


if __name__ == '__main__':
    unittest.main()
