"""Offline checks that the failover feed cannot leak the full subscription."""
import base64
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch
from urllib.parse import unquote, urlsplit
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import failover_subscription as feed


class FailoverSubscriptionTests(unittest.TestCase):
    def setUp(self):
        self.settings = feed.Settings(address="203.0.113.8", title="VPN Авто")
        self.uuid = str(uuid4())
        self.query = ("encryption=none&security=reality&type=tcp&sni=yandex.ru&fp=chrome"
                      "&pbk=" + "A" * 43 + "&sid=abcdef12&packetEncoding=xudp")
        self.compatible = (f"vless://{self.uuid}@203.0.113.8:33173?{self.query}"
                           "#mc-ubuntu-breeze-reef-android-fixture")
        self.legacy = self.compatible.replace(":33173", ":33172")

    @staticmethod
    def wrapped(*lines):
        return base64.b64encode(("\n".join(lines) + "\n").encode())

    def test_mixed_feed_yields_only_one_profile_with_credentials_unchanged(self):
        original = self.wrapped("ss://fixture@example.invalid", self.legacy, self.compatible)
        body = feed.rewrite_profile(original, self.settings)
        lines = base64.b64decode(body).decode().splitlines()
        self.assertEqual(len(lines), 1)
        new = urlsplit(lines[0])
        self.assertEqual((new.scheme, new.hostname, new.port), ("vless", "203.0.113.8", 33174))
        self.assertEqual(new.username, self.uuid)
        self.assertEqual(new.query, self.query)
        self.assertEqual(unquote(new.fragment), "VPN Авто")
        self.assertEqual(feed.rewrite_profile(self.compatible.encode(), self.settings), body)

    def test_missing_duplicate_and_invalid_compatible_profiles_fail_closed(self):
        with self.assertRaises(feed.MissingSubscription):
            feed.rewrite_profile(self.wrapped(self.legacy), self.settings)
        with self.assertRaises(feed.MissingSubscription):
            feed.rewrite_profile(self.wrapped(self.compatible.replace("203.0.113.8", "example.invalid")), self.settings)
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
        connect.assert_called_once_with(self.settings.address, 2096, context=context, timeout=feed.REQUEST_TIMEOUT)
        connection.request.assert_called_once_with("GET", "/sub/fixture_id", headers={
            "Accept": "text/plain", "Accept-Encoding": "identity", "User-Agent": "NekoBox", "X-HWID": "fixture",
        })
        response.read.assert_called_once_with(feed.MAX_BODY + 1)
        connection.close.assert_called_once()
        self.assertIn(b":33174?", base64.b64decode(body))
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


if __name__ == "__main__":
    unittest.main()
