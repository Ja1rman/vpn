#!/usr/bin/env python3
"""Serve a one-profile HTTPS subscription derived from the local x-ui feed.

The old URL and panel are unchanged. The SubID is an existing bearer secret;
it is never recorded in this service's logs or included in errors.
"""
import argparse
import base64
from dataclasses import dataclass
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import re
import socket
import ssl
from threading import BoundedSemaphore, Lock, Timer
from urllib.parse import parse_qs, quote, unquote, urlsplit, urlunsplit
from uuid import UUID


MAX_BODY = 128 * 1024
REQUEST_TIMEOUT = 6
MAX_CONCURRENT = 16
# Both paths on :2097 produce the same filtered feed. The full x-ui feed
# remains on :2096/sub/ and is never served by this handler.
SUB_PATH = re.compile(r"/(?:failover|sub)/([A-Za-z0-9_-]{1,128})")
ANDROID_PREFIX = "mc-ubuntu-breeze-reef-android-"
PASS_REQUEST_HEADERS = ("User-Agent", "X-HWID", "X-Device-OS", "X-Ver-OS", "X-Device-Model")
PASS_RESPONSE_HEADERS = ("Subscription-Userinfo", "Profile-Update-Interval", "Support-Url", "Announce")


class MissingSubscription(Exception):
    """x-ui does not offer a usable source profile to this request."""


class InvalidSubscription(Exception):
    """The x-ui response is unexpected; never return its unfiltered body."""


@dataclass(frozen=True)
class Settings:
    address: str = "212.22.70.156"
    upstream_port: int = 2096
    source_port: int = 33173
    target_port: int = 33174
    title: str = "VPN Auto"


def header_value(value):
    if value and len(value) <= 1024 and all(32 <= ord(c) < 127 for c in value):
        return value
    return None


def rewrite_profile(body, settings):
    """Validate exactly one compatible share link and return it as Base64."""
    if not body.strip():
        raise MissingSubscription()
    if len(body) > MAX_BODY:
        raise InvalidSubscription()
    try:
        if b"://" not in body:
            compact = b"".join(body.split())
            body = base64.b64decode(compact + b"=" * (-len(compact) % 4), validate=True)
        lines = body.decode("utf-8-sig").splitlines()
    except ValueError:
        raise InvalidSubscription() from None
    matching = []
    for line in lines:
        if not line.startswith("vless://"):
            continue
        try:
            parsed = urlsplit(line)
            if parsed.hostname != settings.address.lower() or parsed.port != settings.source_port:
                continue
            if not unquote(parsed.fragment).startswith(ANDROID_PREFIX):
                continue
            if parsed.password is not None or parsed.path or not parsed.username:
                raise InvalidSubscription()
            UUID(parsed.username)
            query = parse_qs(parsed.query, keep_blank_values=True, max_num_fields=32)
            required = {"security": ["reality"], "type": ["tcp"], "encryption": ["none"],
                        "sni": ["yandex.ru"], "fp": ["chrome"]}
            if any(query.get(key) != value for key, value in required.items()):
                raise InvalidSubscription()
            if not re.fullmatch(r"[A-Za-z0-9_-]{43}", query.get("pbk", [""])[0]):
                raise InvalidSubscription()
            if not re.fullmatch(r"(?:[A-Fa-f0-9]{2}){0,8}", query.get("sid", [""])[0]):
                raise InvalidSubscription()
            if len(query.get("pbk", [])) != 1 or len(query.get("sid", [])) != 1:
                raise InvalidSubscription()
        except (TypeError, ValueError):
            raise InvalidSubscription() from None
        matching.append(parsed)
    if not matching:
        raise MissingSubscription()
    if len(matching) != 1:
        raise InvalidSubscription()
    selected = matching[0]
    authority = selected.netloc.rsplit(":", 1)[0] + ":" + str(settings.target_port)
    url = urlunsplit((selected.scheme, authority, selected.path, selected.query,
                      quote(settings.title, safe="")))
    return base64.b64encode((url + "\n").encode())


class LoopbackHTTPSConnection(http.client.HTTPSConnection):
    """Pin the actual network destination while validating the public IP cert."""
    def connect(self):
        raw = socket.create_connection(("127.0.0.1", self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


def fetch_profile(sub_id, headers, settings, upstream_context):
    request_headers = {"Accept": "text/plain", "Accept-Encoding": "identity"}
    for name in PASS_REQUEST_HEADERS:
        value = header_value(headers.get(name))
        if value:
            request_headers[name] = value
    connection = LoopbackHTTPSConnection(settings.address, settings.upstream_port,
                                         context=upstream_context, timeout=REQUEST_TIMEOUT)
    try:
        connection.request("GET", "/sub/" + sub_id, headers=request_headers)
        result = connection.getresponse()
        if result.status in (400, 401, 403, 404, 410):
            raise MissingSubscription()
        if result.status != 200 or result.getheader("Content-Encoding", "identity").lower() != "identity":
            raise InvalidSubscription()
        response_headers = {name: value for name in PASS_RESPONSE_HEADERS
                            if (value := header_value(result.getheader(name)))}
        body = rewrite_profile(result.read(MAX_BODY + 1), settings)
    except (http.client.HTTPException, OSError):
        raise InvalidSubscription() from None
    finally:
        connection.close()
    return body, response_headers


class ReloadingTLS:
    """Reload renewed cert/key copies without interrupting existing clients."""
    def __init__(self, cert, key):
        self.cert, self.key = cert, key
        self.lock = Lock()
        self.context = self.signature = None
        self.get()

    def get(self):
        with self.lock:
            try:
                stats = [path.stat() for path in (self.cert, self.key)]
                signature = tuple((s.st_dev, s.st_ino, s.st_mtime_ns, s.st_size) for s in stats)
                if signature != self.signature:
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    context.minimum_version = ssl.TLSVersion.TLSv1_2
                    context.load_cert_chain(self.cert, self.key)
                    self.context, self.signature = context, signature
            except OSError:
                if self.context is None:
                    raise
                # A cert and key can be copied one after the other by a renewal hook.
                # Retry on the next connection; keep the last matching pair until then.
            return self.context


class SubscriptionHandler(BaseHTTPRequestHandler):
    server_version = "VPN subscription"
    sys_version = ""

    def log_message(self, *_args):
        pass

    def do_HEAD(self):
        self.do_GET()

    def send_error(self, code, message=None, explain=None):
        self.reply(code, b"Invalid subscription request\n")

    def do_GET(self):
        match = SUB_PATH.fullmatch(self.path)
        if not match:
            self.reply(404, b"Subscription not found\n")
            return
        try:
            body, headers = fetch_profile(match[1], self.headers, self.server.settings,
                                          self.server.upstream_context)
        except MissingSubscription:
            self.reply(404, b"Subscription not found\n")
        except InvalidSubscription:
            self.reply(502, b"Subscription temporarily unavailable\n")
        else:
            headers["Profile-Title"] = "base64:" + base64.b64encode(self.server.settings.title.encode()).decode()
            self.reply(200, body, headers)

    def reply(self, status, body, headers=None):
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "private, no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)


def abort_request(connection):
    try:
        connection.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass


class SubscriptionServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 32

    def __init__(self, address, settings, tls, upstream_context):
        self.settings, self.tls, self.upstream_context = settings, tls, upstream_context
        self.slots = BoundedSemaphore(MAX_CONCURRENT)
        super().__init__(address, SubscriptionHandler)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            request.settimeout(REQUEST_TIMEOUT)
            with self.tls.get().wrap_socket(request, server_side=True) as wrapped:
                deadline = Timer(REQUEST_TIMEOUT * 2, abort_request, args=(wrapped,))
                deadline.daemon = True
                deadline.start()
                try:
                    self.finish_request(wrapped, address)
                finally:
                    deadline.cancel()
        except Exception:
            self.handle_error(request, address)
        finally:
            self.shutdown_request(request)
            self.slots.release()

    def handle_error(self, *_args):
        # http.server's default handler dumps tracebacks and peer information.
        pass


def tcp_port(value):
    port = int(value)
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("expected a valid TCP port")
    return port


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen", default="0.0.0.0")
    parser.add_argument("--port", type=tcp_port, default=2097)
    parser.add_argument("--address", default=Settings.address, help="Public gateway address and upstream TLS name")
    parser.add_argument("--upstream-port", type=tcp_port, default=Settings.upstream_port)
    parser.add_argument("--source-port", type=tcp_port, default=Settings.source_port)
    parser.add_argument("--target-port", type=tcp_port, default=Settings.target_port)
    parser.add_argument("--title", default=Settings.title)
    parser.add_argument("--tls-cert", required=True, type=Path)
    parser.add_argument("--tls-key", required=True, type=Path)
    parser.add_argument("--upstream-ca", type=Path, help="Optional CA bundle for the loopback x-ui service")
    args = parser.parse_args()
    if args.source_port == args.target_port or args.port == args.upstream_port:
        parser.error("source and target ports must be distinct; subscription server needs its own port")
    if not args.title.strip() or len(args.title) > 80 or any(ord(char) < 32 for char in args.title):
        parser.error("invalid subscription title")
    settings = Settings(args.address, args.upstream_port, args.source_port, args.target_port, args.title)
    tls = ReloadingTLS(args.tls_cert, args.tls_key)
    upstream_context = ssl.create_default_context(cafile=args.upstream_ca)
    with SubscriptionServer((args.listen, args.port), settings, tls, upstream_context) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
