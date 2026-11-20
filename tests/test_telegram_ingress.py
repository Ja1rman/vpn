"""No-network contracts for the public native Telegram ingress verifier."""
import json
import io
import os
from pathlib import Path
import secrets
import socket
import ssl
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from test_environment import configure
configure()
from vpn_env import env, port
import verify_telegram_ingress as verifier


class FragmentedSocksSocket:
    def __init__(self, response, *, timeout_at_end=False):
        self.response = bytearray(response)
        self.timeout_at_end = timeout_at_end
        self.sent = []
        self.closed = False

    def settimeout(self, value):
        pass

    def connect(self, endpoint):
        self.endpoint = endpoint

    def sendall(self, body):
        self.sent.append(body)

    def recv(self, length):
        if not self.response and self.timeout_at_end:
            raise socket.timeout()
        value = bytes(self.response[:min(length, 1)])
        del self.response[:len(value)]
        return value

    def close(self):
        self.closed = True


def socks_authentication_reply():
    return b'\x05\x02\x01\x00'


def socks_connect_reply():
    return (b'\x05\x00\x00\x01' + socket.inet_aton(env('VPN_LOOPBACK_IP'))
            + port('VPN_TEST_CANARY_PORT').to_bytes(2, 'big'))


def dummy_socks_access(path):
    verifier.private_write(path, {'server': env('VPN_NL_ADDRESS'),
                                 'port': port('VPN_NL_TELEGRAM_PUBLIC_PORT'),
                                 'username': secrets.token_hex(8), 'password': secrets.token_urlsafe(32)})


class PublicIngressTests(unittest.TestCase):
    def test_socks_https_authenticates_connects_and_checks_trusted_tls(self):
        raw = FragmentedSocksSocket(socks_authentication_reply() + socks_connect_reply())
        secured = Mock()
        secured.makefile.return_value = io.BytesIO(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')
        context = Mock()
        context.wrap_socket.return_value = secured
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'access.json'
            dummy_socks_access(path)
            with patch.object(verifier.socket, 'socket', return_value=raw), \
                    patch.object(verifier.ssl, 'create_default_context', return_value=context):
                result = verifier.socks_https_check(path)
        self.assertTrue(result['passed'])
        for field in ('credentials_accepted', 'connect_request_sent', 'connect_reply_received',
                      'target_connect_accepted', 'trusted_tls', 'https_response_received'):
            self.assertTrue(result[field])
        self.assertEqual(raw.endpoint, (env('VPN_NL_ADDRESS'), port('VPN_NL_TELEGRAM_PUBLIC_PORT')))
        self.assertEqual(raw.sent[-1][-2:], port('VPN_TELEGRAM_VERIFY_HTTPS_PORT').to_bytes(2, 'big'))
        self.assertIn(b'docs.python.org', raw.sent[-1])
        context.wrap_socket.assert_called_once_with(raw, server_hostname='docs.python.org')
        secured.close.assert_called_once()

    def test_socks_https_distinguishes_connect_timeout_from_authentication(self):
        raw = FragmentedSocksSocket(socks_authentication_reply(), timeout_at_end=True)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'access.json'
            dummy_socks_access(path)
            with patch.object(verifier.socket, 'socket', return_value=raw), \
                    patch.object(verifier.ssl, 'create_default_context') as tls:
                result = verifier.socks_https_check(path)
        self.assertFalse(result['passed'])
        self.assertTrue(result['credentials_accepted'])
        self.assertTrue(result['connect_request_sent'])
        self.assertFalse(result['connect_reply_received'])
        self.assertEqual(result['error_class'], 'timeout')
        self.assertTrue(raw.closed)
        tls.assert_not_called()

    def test_socks_https_refuses_bad_certificate_without_success(self):
        raw = FragmentedSocksSocket(socks_authentication_reply() + socks_connect_reply())
        context = Mock()
        context.wrap_socket.side_effect = ssl.SSLCertVerificationError('untrusted dummy certificate')
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'access.json'
            dummy_socks_access(path)
            with patch.object(verifier.socket, 'socket', return_value=raw), \
                    patch.object(verifier.ssl, 'create_default_context', return_value=context):
                result = verifier.socks_https_check(path)
        self.assertFalse(result['passed'])
        self.assertTrue(result['target_connect_accepted'])
        self.assertFalse(result['trusted_tls'])
        self.assertEqual(result['error_class'], 'certificate_verification')
        self.assertTrue(raw.closed)

    def test_reserve_uses_dedicated_public_ingress_role(self):
        address, ingress_port, _ = verifier.host_settings('nl')
        self.assertEqual(address, env('VPN_NL_ADDRESS'))
        self.assertEqual(ingress_port, port('VPN_NL_TELEGRAM_PUBLIC_PORT'))
        self.assertNotEqual(ingress_port, port('VPN_NL_RELAY_TLS_PORT'))

    def test_local_copy_changes_only_endpoint_and_keeps_distinct_keys(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'access.json'
            value = {'server': env('VPN_ENTRY_ADDRESS'), 'port': port('VPN_MTPROTO_DD_PORT'),
                     'secret': 'dd' + secrets.token_hex(16), 'extra': 'discard'}
            verifier.private_write(path, value)
            before = path.read_bytes()
            copied = verifier.access_for_ingress(path, 'dd', env('VPN_NL_ADDRESS'),
                                                 port('VPN_NL_TELEGRAM_PUBLIC_PORT'))
            self.assertEqual(copied['secret'], value['secret'])
            self.assertEqual(copied['server'], env('VPN_NL_ADDRESS'))
            self.assertEqual(copied['port'], port('VPN_NL_TELEGRAM_PUBLIC_PORT'))
            self.assertNotIn('extra', copied)
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            path.chmod(0o644)
            with self.assertRaises(RuntimeError):
                verifier.access_for_ingress(path, 'dd', env('VPN_NL_ADDRESS'), port('VPN_NL_TELEGRAM_PUBLIC_PORT'))

    def test_real_client_contract_requires_rpc_and_never_adds_nested_hop(self):
        row = {'status': 'passed', 'account_login': False, 'key_exchange': 'passed',
               'rpc': 'help.getNearestDC', 'this_dc': 2, 'elapsed_ms': 123}
        with patch.object(verifier.subprocess, 'run', return_value=SimpleNamespace(
                returncode=0, stdout=json.dumps(row).encode())) as run:
            self.assertTrue(verifier.native_check(Path('probe'), 'dd', Path('private.json'))['passed'])
            arguments = run.call_args.args[0]
            self.assertNotIn('--via-socks', arguments)
            self.assertNotIn('--interface', arguments)
        row.pop('rpc')
        with patch.object(verifier.subprocess, 'run', return_value=SimpleNamespace(
                returncode=0, stdout=json.dumps(row).encode())):
            self.assertFalse(verifier.native_check(Path('probe'), 'dd', Path('private.json'))['passed'])

    def test_output_filters_untrusted_client_failure_details(self):
        row = {'status': 'failed', 'error_class': 'secret-like-detail', 'private': secrets.token_hex(16)}
        with patch.object(verifier.subprocess, 'run', return_value=SimpleNamespace(
                returncode=1, stdout=json.dumps(row).encode())):
            result = verifier.native_check(Path('probe'), 'socks', Path('private.json'))
            self.assertEqual(result, {'passed': False, 'key_exchange_and_anonymous_rpc': False,
                                      'error_class': 'client_failure'})


if __name__ == '__main__':
    unittest.main()
