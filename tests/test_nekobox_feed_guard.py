import base64
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from urllib.parse import urlencode
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from test_environment import configure
configure()
import install_failover_subscription as installer
from vpn_env import port


class NekoBoxFeedGuard(unittest.TestCase):
    def setUp(self):
        self.uid = str(uuid4())
        query = urlencode({'type': 'tcp', 'security': 'tls', 'encryption': 'none',
                           'packetEncoding': 'xudp', 'sni': installer.ADDRESS, 'fp': 'chrome'})
        uri = f'vless://{self.uid}@{installer.ADDRESS}:{installer.AUTO_TLS_PORT}?{query}#VPN%20Auto'
        self.body = base64.b64encode((uri + '\n').encode())
        self.expected = {'outbounds': [{'type': 'vless', 'tag': 'VPN Auto',
            'server': installer.ADDRESS, 'server_port': installer.AUTO_TLS_PORT, 'uuid': self.uid,
            'packet_encoding': 'xudp', 'multiplex': {'enabled': False},
            'tls': {'enabled': True, 'server_name': installer.ADDRESS, 'insecure': False,
                    'utls': {'enabled': True, 'fingerprint': 'chrome'}}}]}

    def check(self, payload):
        def response(listen_port, identifier, agent=None):
            return self.body if agent is None else json.dumps(payload).encode()
        with patch.object(installer, 'subscription_body', side_effect=response):
            installer.check_nekobox_feeds(port('VPN_AUTO_SUBSCRIPTION_PORT'), {'fixture': self.body})

    def test_app_specific_json_preserves_identity_and_disables_multiplex(self):
        self.check(self.expected)

    def test_rejects_credentials_routing_or_transport_changes(self):
        candidates = []
        for key, value in [('uuid', str(uuid4())), ('server', 'other.example.test'),
                           ('multiplex', {'enabled': True}), ('tag', 'Different profile')]:
            changed = copy.deepcopy(self.expected)
            changed['outbounds'][0][key] = value
            candidates.append(changed)
        changed = copy.deepcopy(self.expected)
        changed['outbounds'].append({'type': 'direct', 'tag': 'bypass'})
        candidates.append(changed)
        changed = copy.deepcopy(self.expected)
        changed['outbounds'][0]['tls']['insecure'] = True
        candidates.append(changed)
        for candidate in candidates:
            with self.subTest(candidate=list(candidate)), self.assertRaises(RuntimeError):
                self.check(candidate)

    def test_reality_fallback_remains_byte_identical(self):
        reality = self.body = base64.b64encode(base64.b64decode(self.body).replace(
            b'security=tls', b'security=reality'))
        with patch.object(installer, 'subscription_body', return_value=reality):
            installer.check_nekobox_feeds(port('VPN_AUTO_SUBSCRIPTION_PORT'), {'fixture': reality})


if __name__ == '__main__':
    unittest.main()
