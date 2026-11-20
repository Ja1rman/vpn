"""Offline checks that the failover feed cannot leak the full subscription."""
import base64
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch
from urllib.parse import unquote, urlsplit
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from test_environment import configure
configure()
from vpn_env import env, port as env_port, expand
import failover_subscription as feed
import install_failover_subscription as installer


class FailoverSubscriptionTests(unittest.TestCase):
    def setUp(self):
        self.settings = feed.Settings(address=env('VPN_TEST_ADDRESS_D'), title="VPN Авто")
        self.uuid = str(uuid4())
        self.query = ("encryption=none&security=reality&type=tcp&sni=yandex.ru&fp=chrome"
                      "&pbk=" + "A" * 43 + "&sid=abcdef12&packetEncoding=xudp")
        self.compatible = (f"vless://{self.uuid}@{self.settings.address}:{self.settings.source_port}?{self.query}"
                           "#mc-ubuntu-breeze-reef-android-fixture")
        self.legacy = self.compatible.replace(f":{self.settings.source_port}",
                                              ":" + str(env_port('VPN_VLESS_NATIVE_PORT')))
        self.plain = (f"vless://{self.uuid}@{self.settings.address}:{self.settings.tls_source_port}?type=tcp&security=none"
                      "&encryption=none&headerType=none#x-ui-fixture")

    @staticmethod
    def wrapped(*lines):
        return base64.b64encode(("\n".join(lines) + "\n").encode())

    def test_aliases_serve_the_same_single_profile(self):
        body = feed.rewrite_profile(self.wrapped(self.legacy, self.compatible), self.settings)
        responses = []
        with patch.object(feed, "fetch_profile", return_value=(body, {})) as fetch:
            for prefix in ("sub", "failover"):
                handler = Mock(path=f"/{prefix}/fixture_id")
                handler.server.settings = self.settings
                feed.SubscriptionHandler.do_GET(handler)
                responses.append(handler.reply.call_args)
            self.assertEqual(responses[0], responses[1])
            self.assertEqual(responses[0].args[:2], (200, body))
            self.assertEqual([call.args[0] for call in fetch.call_args_list], ["fixture_id", "fixture_id"])
            for invalid in ("/sub/../fixture_id", "/sub/fixture_id?extra=1"):
                handler = Mock(path=invalid)
                feed.SubscriptionHandler.do_GET(handler)
                self.assertEqual(handler.reply.call_args.args[0], 404)
            self.assertEqual(fetch.call_count, 2)

    def test_mixed_feed_yields_only_one_profile_with_credentials_unchanged(self):
        original = self.wrapped("ss://fixture@example.invalid", self.legacy, self.compatible, self.plain)
        body = feed.rewrite_profile(original, self.settings)
        lines = base64.b64decode(body).decode().splitlines()
        self.assertEqual(len(lines), 1)
        new = urlsplit(lines[0])
        self.assertEqual((new.scheme, new.hostname, new.port),
                         ("vless", self.settings.address, self.settings.tls_target_port))
        self.assertEqual(new.username, self.uuid)
        self.assertEqual(new.query, "type=tcp&security=tls&encryption=none&packetEncoding=xudp"
                         + "&sni=" + self.settings.address + "&fp=chrome")
        self.assertEqual(unquote(new.fragment), "VPN Авто")
        self.assertEqual(feed.rewrite_profile(self.plain.encode(), self.settings), body)

    def test_legacy_only_subscription_keeps_its_reality_profile(self):
        body = feed.rewrite_profile(self.wrapped(self.legacy, self.compatible), self.settings)
        lines = base64.b64decode(body).decode().splitlines()
        self.assertEqual(len(lines), 1)
        selected = urlsplit(lines[0])
        self.assertEqual(selected.port, self.settings.target_port)
        self.assertEqual(selected.username, self.uuid)
        self.assertEqual(selected.query, self.query)
        self.assertEqual(unquote(selected.fragment), self.settings.title)

    def test_new_xui_client_gets_a_single_trusted_tls_profile(self):
        body = feed.rewrite_profile(self.wrapped(self.legacy, self.plain), self.settings)
        lines = base64.b64decode(body).decode().splitlines()
        self.assertEqual(len(lines), 1)
        new = urlsplit(lines[0])
        self.assertEqual((new.scheme, new.hostname, new.port),
                         ("vless", self.settings.address, self.settings.tls_target_port))
        self.assertEqual(new.username, self.uuid)
        self.assertEqual(new.query, "type=tcp&security=tls&encryption=none&packetEncoding=xudp"
                         + "&sni=" + self.settings.address + "&fp=chrome")
        self.assertEqual(unquote(new.fragment), "VPN Авто")

    def test_native_xui_tls_host_is_a_source_for_new_auto_clients(self):
        source = self.plain.replace(f":{self.settings.tls_source_port}",
                                    f":{self.settings.tls_standard_port}").replace("security=none", "security=tls")
        expected = feed.rewrite_profile(self.plain.encode(), self.settings)
        self.assertEqual(feed.rewrite_profile(source.encode(), self.settings), expected)
        self.assertEqual(feed.rewrite_profile(self.wrapped(source, self.plain), self.settings), expected)
        self.assertEqual(feed.rewrite_profile(self.wrapped(self.compatible, source), self.settings), expected)
        invalid = (
            source.replace("security=tls", "security=none"),
            source.replace("#x-ui", "&allowInsecure=1#x-ui"),
            source.replace("#x-ui", "&sni=example.invalid#x-ui"),
            source.replace(self.uuid, str(uuid4())),
        )
        for link in invalid:
            with self.assertRaises(feed.InvalidSubscription):
                feed.rewrite_profile(self.wrapped(self.compatible, self.plain, link), self.settings)

    def test_tls_fallback_never_uses_an_unverified_or_ambiguous_source(self):
        with self.assertRaises(feed.MissingSubscription):
            feed.rewrite_profile(self.wrapped(self.plain.replace(self.settings.address, "example.invalid")), self.settings)
        for links in (
                [self.plain, self.plain],
                [self.plain.replace("type=tcp", "type=ws")],
                [self.plain.replace("security=none", "security=tls")],
                [self.plain.replace("#x-ui", "&flow=xtls-rprx-vision#x-ui")],
                [self.plain, self.compatible.replace("security=reality", "security=none")],
        ):
            with self.assertRaises(feed.InvalidSubscription):
                feed.rewrite_profile(self.wrapped(self.compatible, *links), self.settings)

    def test_missing_duplicate_and_invalid_compatible_profiles_fail_closed(self):
        with self.assertRaises(feed.MissingSubscription):
            feed.rewrite_profile(self.wrapped(self.legacy), self.settings)
        with self.assertRaises(feed.MissingSubscription):
            feed.rewrite_profile(self.wrapped(self.compatible.replace(self.settings.address, "example.invalid")), self.settings)
        for invalid in (
                self.wrapped(self.compatible, self.compatible),
                self.wrapped(self.compatible.replace("security=reality", "security=none")),
                self.wrapped(self.compatible.replace("&sid=", "&sid=1234&sid=")),
                b"<html>not an x-ui feed</html>", b"A" * (feed.MAX_BODY + 1),
        ):
            with self.subTest(case=len(invalid)), self.assertRaises(feed.InvalidSubscription):
                feed.rewrite_profile(invalid, self.settings)

    def test_upstream_receives_only_safe_headers_and_metadata_is_filtered(self):
        response_headers = {
            "Subscription-Userinfo": "upload=1; download=2; total=0; expire=0",
            "Profile-Update-Interval": "12", "Profile-Web-Page-Url": "https://example.invalid/old",
            "Announce": "line\r\ninjection", "Set-Cookie": "discard-me",
        }
        incoming = {"User-Agent": "NekoBox", "X-HWID": "fixture", "Cookie": "discard-me",
                    "Host": "example.invalid", "X-Device-Model": "line\r\ninjection"}
        connection, context = Mock(), Mock()
        response = connection.getresponse.return_value
        response.status = 200
        response.getheader.side_effect = lambda name, default=None: response_headers.get(name, default)
        response.read.return_value = self.wrapped(self.compatible)
        with patch.object(feed, "LoopbackHTTPSConnection", return_value=connection) as connect:
            body, headers = feed.fetch_profile("fixture_id", incoming, self.settings, context)
        connect.assert_called_once_with(self.settings.address, self.settings.upstream_port,
                                        context=context, timeout=feed.REQUEST_TIMEOUT)
        connection.request.assert_called_once_with("GET", "/sub/fixture_id", headers={
            "Accept": "text/plain", "Accept-Encoding": "identity", "User-Agent": "NekoBox", "X-HWID": "fixture",
        })
        response.read.assert_called_once_with(feed.MAX_BODY + 1)
        connection.close.assert_called_once()
        self.assertIn(f":{self.settings.target_port}?".encode(), base64.b64decode(body))
        self.assertEqual(set(headers), {"Subscription-Userinfo", "Profile-Update-Interval"})

    def test_upstream_redirects_are_never_followed(self):
        connection = Mock()
        connection.getresponse.return_value.status = 302
        with patch.object(feed, "LoopbackHTTPSConnection", return_value=connection):
            with self.assertRaises(feed.InvalidSubscription):
                feed.fetch_profile("fixture_id", {}, self.settings, Mock())
        connection.request.assert_called_once()
        connection.getresponse.return_value.read.assert_not_called()
        connection.close.assert_called_once()

    def test_supported_nekobox_gets_one_secure_outbound_with_same_profile_name(self):
        source = feed.rewrite_profile(self.wrapped(self.plain), self.settings)
        for version in ('1.3.8', '1.3.9', '1.4.2', '2.0.0'):
            body, content_type = feed.nekobox_response(
                source, self.settings, 'NekoBox/Android/' + version + ' (Prefer ClashMeta Format)')
            self.assertEqual(content_type, feed.JSON_CONTENT_TYPE)
            self.assertEqual(json.loads(body), {'outbounds': [{
                'type': 'vless', 'tag': self.settings.title, 'server': self.settings.address,
                'server_port': self.settings.tls_target_port, 'uuid': self.uuid, 'packet_encoding': 'xudp',
                'multiplex': {'enabled': False}, 'tls': {
                    'enabled': True, 'server_name': self.settings.address, 'insecure': False,
                    'utls': {'enabled': True, 'fingerprint': 'chrome'},
                },
            }]})

    def test_older_unknown_and_other_clients_keep_uri_bytes(self):
        source = feed.rewrite_profile(self.wrapped(self.plain), self.settings)
        for agent in (None, '', 'NekoBox', 'NekoBox/Android/1.3.7 (Prefer ClashMeta Format)',
                      'NekoBox/Android/01.4.2', 'NekoBox/Android/1.4.2-beta', 'NekoBox/Android/1.4',
                      'NekoBox/Android/1.4.2 unknown', 'Hiddify/2.0.0', 'v2rayNG/1.0.0',
                      'Other NekoBox/Android/1.4.2', 'NekoBox/Android/1.4.2\r\nextra'):
            self.assertEqual(feed.nekobox_response(source, self.settings, agent),
                             (source, feed.URI_CONTENT_TYPE))
        reality = feed.rewrite_profile(self.wrapped(self.compatible), self.settings)
        self.assertEqual(feed.nekobox_response(reality, self.settings, 'NekoBox/Android/1.4.2'),
                         (reality, feed.URI_CONTENT_TYPE))

    def test_nekobox_converter_refuses_unverified_or_ambiguous_tls_sources(self):
        source = base64.b64decode(feed.rewrite_profile(self.wrapped(self.plain), self.settings)).decode().strip()
        for invalid in (source.replace(self.uuid, 'not-a-uuid'),
                        source.replace(self.settings.address, 'example.invalid'),
                        source.replace(':' + str(self.settings.tls_target_port), ':' + str(env_port('VPN_TEST_UNEXPECTED_PORT'))),
                        source.replace('&sni=' + self.settings.address, ''),
                        source.replace('&fp=chrome', '&fp=chrome&fp=firefox'),
                        source.replace('&fp=chrome', '&fp=chrome&allowInsecure=1'),
                        source + '\n' + source):
            with self.assertRaises(feed.InvalidSubscription):
                feed.nekobox_response(self.wrapped(invalid), self.settings, 'NekoBox/Android/1.4.2')
        with self.assertRaises(feed.InvalidSubscription):
            feed.nekobox_response(b'not a subscription', self.settings, 'NekoBox/Android/1.4.2')

    def test_nekobox_fetch_and_reply_emit_one_safe_json_content_type(self):
        connection, context = Mock(), Mock()
        response = connection.getresponse.return_value
        response.status = 200
        response.getheader.side_effect = lambda _name, default=None: default
        response.read.return_value = self.wrapped(self.plain)
        with patch.object(feed, 'LoopbackHTTPSConnection', return_value=connection):
            body, headers = feed.fetch_profile('fixture_id', {'User-Agent': 'NekoBox/Android/1.4.2'},
                                                self.settings, context)
        self.assertEqual(headers, {'Content-Type': feed.JSON_CONTENT_TYPE})
        self.assertEqual(len(json.loads(body)['outbounds']), 1)
        for extra, expected in ((headers, feed.JSON_CONTENT_TYPE),
                                ({'Content-Type': 'text/html', 'content-type': 'text/html'}, feed.URI_CONTENT_TYPE)):
            handler = Mock(command='HEAD')
            feed.SubscriptionHandler.reply(handler, 200, body, extra)
            content_types = [call.args[1] for call in handler.send_header.call_args_list
                             if call.args[0].lower() == 'content-type']
            self.assertEqual(content_types, [expected])
            handler.wfile.write.assert_not_called()


class SubscriptionUpgradeGuardTests(unittest.TestCase):
    def setUp(self):
        self.uuid = str(uuid4())
        self.previous = (f'vless://{self.uuid}@{installer.ADDRESS}:{env_port("VPN_AUTO_TLS_PORT")}'
                         '?type=tcp&security=tls&encryption=none&packetEncoding=xudp#VPN%20Auto')
        self.current = (f'vless://{self.uuid}@{installer.ADDRESS}:{installer.AUTO_TLS_PORT}'
                        '?type=tcp&security=tls&encryption=none&packetEncoding=xudp'
                        f'&sni={installer.ADDRESS}&fp=chrome#VPN%20Auto')

    @staticmethod
    def encoded(*lines):
        return base64.b64encode(('\n'.join(lines) + '\n').encode())

    def check(self, body, *, allow=False, previous=None):
        previous = self.encoded(self.previous if previous is None else previous)
        with patch.object(installer, 'subscription_body', return_value=body):
            installer.check_existing_feeds(env_port('VPN_AUTO_SUBSCRIPTION_PORT'),
                                           {'fixture_id': previous}, allow)

    def test_unchanged_feed_is_allowed_but_profile_change_requires_flag(self):
        self.check(self.encoded(self.previous))
        with self.assertRaisesRegex(RuntimeError, 'profile changed'):
            self.check(self.encoded(self.current))
        self.check(self.encoded(self.current), allow=True)
        previous_reality = self.previous.replace('security=tls', 'security=reality')
        self.check(self.encoded(self.current), allow=True, previous=previous_reality)

    def test_flag_cannot_change_credentials_or_weaken_tls_profile(self):
        for current in (
            self.current.replace(self.uuid, str(uuid4())),
            self.current.replace(installer.ADDRESS, env('VPN_TEST_ADDRESS_D')),
            self.current.replace(':' + str(installer.AUTO_TLS_PORT), ':' + str(env_port('VPN_TEST_UNEXPECTED_PORT'))),
            self.current.replace('security=tls', 'security=none'),
            self.current.replace('sni=' + installer.ADDRESS, 'sni=example.invalid'),
            self.current.replace('&sni=' + installer.ADDRESS, ''),
            self.current.replace('fp=chrome', 'fp=firefox'),
            self.current.replace('packetEncoding=xudp', 'packetEncoding=packetaddr'),
            self.current.replace('#VPN', '&allowInsecure=1#VPN'),
            self.current.replace('#VPN', '&fp=chrome#VPN'),
            self.current.replace(self.uuid + '@', self.uuid + ':extra@'),
        ):
            with self.subTest(case=current != self.current), self.assertRaisesRegex(RuntimeError, 'verified TLS endpoint'):
                self.check(self.encoded(current), allow=True)
        for body in (None, self.encoded(self.current, self.current), b'not a subscription'):
            with self.assertRaisesRegex(RuntimeError, 'verified TLS endpoint'):
                self.check(body, allow=True)


if __name__ == "__main__":
    unittest.main()
