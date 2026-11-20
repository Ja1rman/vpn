"""Guard shared nginx, DNS identity and ACME scope for WEB co-hosting."""
import os
import hashlib
from pathlib import Path
import secrets
import socket
import sys
import tempfile
import unittest
from unittest.mock import patch
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from test_environment import configure
configure()
from vpn_env import env, port
import install_web_proxy as relay
import install_web_tls as tls


class WebTLSTest(unittest.TestCase):
    def test_candidate_uses_private_stdin_tmpfs_on_read_only_container(self):
        candidate = 'events {}\nhttp {}\n'
        with patch.object(tls, 'command') as command:
            tls.check_candidate('readonly-nginx', Path('nginx.conf'), candidate)
        calls = command.call_args_list
        self.assertEqual(calls[0].args[:4], ('docker', 'exec', '-i', 'readonly-nginx'))
        self.assertEqual(calls[0].kwargs['data'], candidate.encode())
        self.assertIn('umask 077; set -C;', calls[0].args[6])
        self.assertNotIn(candidate, calls[0].args)
        self.assertIn('nginx', calls[1].args)
        self.assertEqual(calls[-1].args[:5], ('docker', 'exec', 'readonly-nginx', 'rm', '-f'))

    def setUp(self):
        self.settings = relay.Endpoints('web.example', env('VPN_LOOPBACK_IP'),
                                       port('VPN_TEST_SNIFF_PORT'), port('VPN_TEST_EXIT_C_PORT'),
                                       port('VPN_MTPROTO_DD_PORT'), port('VPN_MONITORING_HTTP_PORT'))
        self.credentials = {'secret': 'dd' + secrets.token_hex(16), 'base_path': secrets.token_hex(10),
                            'token_key': secrets.token_hex(32)}

    def test_append_leaves_existing_servers_byte_identical_and_refuses_drift(self):
        original = 'events {}\nhttp {\n  server { location /grafana/ {} }\n}\n'
        block = tls.tls_server(self.credentials, self.settings)
        result = tls.insert_server(original, block)
        self.assertEqual(result.split(tls.BEGIN)[0], original.rsplit('}', 1)[0])
        self.assertEqual(tls.insert_server(result, block), result)
        with self.assertRaisesRegex(RuntimeError, 'differs'):
            tls.insert_server(result, block.replace('TLSv1.3', 'TLSv1.2'))
        with self.assertRaisesRegex(RuntimeError, 'Ambiguous'):
            tls.insert_server(result.rsplit('}', 1)[0] + tls.BEGIN + '}\n', block)

    def test_http_challenge_is_hostname_scoped_and_only_loopback_forwarded(self):
        with patch.dict(os.environ, VPN_WEB_ACME_PORT=env('VPN_TEST_CANARY_PORT')):
            block = tls.challenge_server(self.settings)
            args = tls.acme_arguments(self.settings)
        self.assertIn('server_name web.example;', block)
        self.assertIn('location ^~ /.well-known/acme-challenge/', block)
        self.assertIn('location / { return 404; }', block)
        self.assertIn(f'proxy_pass http://{self.settings.loopback}:', block)
        self.assertEqual(args[args.index('--http-01-address') + 1], self.settings.loopback)
        self.assertIn('--config-dir', args)
        self.assertNotIn('--nginx', args)
        self.assertNotIn('--apache', args)

    def test_dns_rejects_wrong_or_extra_addresses(self):
        def answers(*addresses):
            return [(socket.AF_INET, socket.SOCK_STREAM, 0, '', (address, 0)) for address in addresses]
        with patch.object(tls.socket, 'getaddrinfo', return_value=answers(env('VPN_ENTRY_ADDRESS'))):
            tls.check_dns(self.settings)
        for values in (answers(env('VPN_TEST_ADDRESS_A')),
                       answers(env('VPN_ENTRY_ADDRESS'), env('VPN_TEST_ADDRESS_A'))):
            with patch.object(tls.socket, 'getaddrinfo', return_value=values):
                with self.assertRaisesRegex(RuntimeError, 'only'):
                    tls.check_dns(self.settings)

    def test_failed_reload_restores_same_inode_and_previous_content(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'nginx.conf'
            before, after = 'events {}\nhttp {}\n', 'events {}\nhttp { server {} }\n'
            config.write_text(before)
            inode = config.stat().st_ino
            calls = []

            def command(*args):
                calls.append(args)
                if '-t' in args:
                    raise RuntimeError('validation failed')
                return b''

            with patch.object(tls, 'check_candidate'), patch.object(tls, 'container_pid', return_value=('id', 2)), \
                    patch.object(tls, 'command', side_effect=command):
                with self.assertRaisesRegex(RuntimeError, 'validation failed'):
                    tls.replace_and_reload('owned-nginx', config, after)
            self.assertEqual(config.read_text(), before)
            self.assertEqual(config.stat().st_ino, inode)
            self.assertEqual(calls[-1], ('docker', 'kill', '--signal=HUP', 'owned-nginx'))

    def test_tls_probe_accepts_only_the_expected_served_leaf(self):
        expected = b'new trusted leaf DER'
        channel = MagicMock()
        connection = channel.__enter__.return_value
        connection.getpeercert.return_value = expected
        connection.recv.return_value = b'HTTP/1.1 404 Not Found\r\n'
        context = MagicMock()
        context.wrap_socket.return_value = channel
        with patch.object(tls.socket, 'create_connection') as connect, \
                patch.object(tls.ssl, 'create_default_context', return_value=context):
            tls.verify_https(self.settings, hashlib.sha256(expected).hexdigest())
        connect.assert_called_once()
        self.assertEqual(context.wrap_socket.call_args.kwargs['server_hostname'], self.settings.hostname)
        connection.getpeercert.assert_called_once_with(binary_form=True)
        connection.sendall.assert_called_once()

    def test_tls_probe_retries_a_trusted_old_leaf_until_the_reloaded_leaf_is_served(self):
        expected = b'new trusted leaf DER'
        old_channel, new_channel = MagicMock(), MagicMock()
        old, new = old_channel.__enter__.return_value, new_channel.__enter__.return_value
        old.getpeercert.return_value = b'old but still trusted leaf DER'
        new.getpeercert.return_value = expected
        new.recv.return_value = b'HTTP/1.1 404 Not Found\r\n'
        context = MagicMock()
        context.wrap_socket.side_effect = [old_channel, new_channel]
        with patch.object(tls.socket, 'create_connection') as connect, \
                patch.object(tls.ssl, 'create_default_context', return_value=context), \
                patch.object(tls.time, 'sleep') as delay:
            tls.verify_https(self.settings, hashlib.sha256(expected).hexdigest())
        self.assertEqual(connect.call_count, 2)
        delay.assert_called_once()
        old.sendall.assert_not_called()
        new.sendall.assert_called_once()

    def test_tls_probe_refuses_an_old_leaf_even_if_the_site_would_answer(self):
        channel = MagicMock()
        connection = channel.__enter__.return_value
        connection.getpeercert.return_value = b'old still trusted leaf DER'
        connection.recv.return_value = b'HTTP/1.1 404 Not Found\r\n'
        context = MagicMock()
        context.wrap_socket.return_value = channel
        with patch.object(tls.socket, 'create_connection'), \
                patch.object(tls.ssl, 'create_default_context', return_value=context), \
                patch.object(tls.time, 'sleep'):
            with self.assertRaisesRegex(RuntimeError, 'TLS verification failed'):
                tls.verify_https(self.settings, hashlib.sha256(b'new leaf DER').hexdigest())
        connection.sendall.assert_not_called()

    def test_concurrent_config_change_is_preserved_without_a_reload(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'nginx.conf'
            config.write_text('events {}\nhttp {}\n')
            concurrent = 'events {}\nhttp { server { location /other/ {} } }\n'
            with patch.object(tls, 'check_candidate', side_effect=lambda *args: config.write_text(concurrent)), \
                    patch.object(tls, 'container_pid', return_value=('id', 2)), \
                    patch.object(tls, 'command') as command:
                with self.assertRaisesRegex(RuntimeError, 'changed concurrently'):
                    tls.replace_and_reload('owned-nginx', config, 'events {}\nhttp { server {} }\n')
            self.assertEqual(config.read_text(), concurrent)
            command.assert_not_called()


if __name__ == '__main__':
    unittest.main()
