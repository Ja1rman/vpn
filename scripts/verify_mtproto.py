#!/usr/bin/env python3
"""Probe FakeTLS MTProxy and a real unauthenticated Telegram req_pq_multi RPC.

No Telegram account, authorization key, login, message, or server mutation is
required. Implements the wire protocol documented by Telegram and mtg v2.3.0:
https://core.telegram.org/mtproto/mtproto-transports
https://github.com/9seconds/mtg/tree/v2.3.0/mtglib/internal/tls/fake
https://github.com/9seconds/mtg/tree/v2.3.0/mtglib/obfuscation
"""
import argparse
import base64
import ctypes
import ctypes.util
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import stat
import struct
import sys
import time


RANDOM_OFFSET = 11
REQ_PQ_MULTI = 0xbe7e8ef1
RES_PQ = 0x05162463
VECTOR = 0x1cb5c415


class ProbeError(Exception):
    """Only fixed, non-secret diagnostics may be put in this exception."""
    stage = 'configuration'
    fake_tls = False


def require(condition, message):
    if not condition:
        raise ProbeError(message)


class AESCTR:
    """Use the system OpenSSL EVP implementation; no subprocess key arguments."""
    def __init__(self, key, iv):
        self.ctx = None
        require(len(key) == 32 and len(iv) == 16, 'Invalid AES-256-CTR key or IV length')
        name = ctypes.util.find_library('crypto')
        require(bool(name), 'System OpenSSL libcrypto is unavailable')
        self.lib = ctypes.CDLL(name)
        void = ctypes.c_void_p
        self.lib.EVP_CIPHER_CTX_new.argtypes = []
        self.lib.EVP_CIPHER_CTX_new.restype = void
        self.lib.EVP_CIPHER_CTX_free.argtypes = [void]
        self.lib.EVP_CIPHER_CTX_free.restype = None
        self.lib.EVP_aes_256_ctr.argtypes = []
        self.lib.EVP_aes_256_ctr.restype = void
        self.lib.EVP_EncryptInit_ex.argtypes = [void, void, void, void, void]
        self.lib.EVP_EncryptInit_ex.restype = ctypes.c_int
        self.lib.EVP_EncryptUpdate.argtypes = [void, void, ctypes.POINTER(ctypes.c_int), void, ctypes.c_int]
        self.lib.EVP_EncryptUpdate.restype = ctypes.c_int
        self.ctx = self.lib.EVP_CIPHER_CTX_new()
        require(bool(self.ctx), 'OpenSSL could not allocate the cipher context')
        key_buffer, iv_buffer = ctypes.create_string_buffer(key), ctypes.create_string_buffer(iv)
        if self.lib.EVP_EncryptInit_ex(self.ctx, self.lib.EVP_aes_256_ctr(), None, key_buffer, iv_buffer) != 1:
            self.close()
            raise ProbeError('OpenSSL could not initialize AES-256-CTR')

    def crypt(self, data):
        require(self.ctx is not None and len(data) <= 65536, 'Invalid AES stream operation')
        output = ctypes.create_string_buffer(len(data) + 16)
        source = ctypes.create_string_buffer(data)
        count = ctypes.c_int()
        require(self.lib.EVP_EncryptUpdate(self.ctx, output, ctypes.byref(count), source, len(data)) == 1
                and count.value == len(data), 'OpenSSL AES stream operation failed')
        return output.raw[:count.value]

    def close(self):
        if self.ctx is not None:
            self.lib.EVP_CIPHER_CTX_free(self.ctx)
            self.ctx = None

    def __del__(self):
        self.close()


def parse_secret(text):
    require(isinstance(text, str) and 34 <= len(text) <= 1024, 'Invalid FakeTLS secret format')
    try:
        raw = bytes.fromhex(text)
    except ValueError:
        try:
            raw = base64.b64decode(text + '=' * (-len(text) % 4), altchars=b'-_', validate=True)
        except (ValueError, TypeError):
            raise ProbeError('Invalid FakeTLS secret encoding') from None
    require(len(raw) > 17 and raw[0] == 0xee, 'Only FakeTLS ee secrets are supported')
    try:
        hostname = raw[17:].decode('ascii')
    except UnicodeError:
        raise ProbeError('FakeTLS secret contains an invalid hostname') from None
    require(len(hostname) <= 253 and re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?', hostname),
            'FakeTLS secret contains an invalid hostname')
    return raw[1:17], hostname


def load_secret(path, *, config=False):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and not info.st_mode & 0o007 and info.st_size <= 1024 * 1024,
            'Secret input must be a private regular file')
    text = path.read_text()
    if config:
        matches = re.findall(r'^secret\s*=\s*"([a-zA-Z0-9_-]+)"\s*(?:#.*)?$', text, re.MULTILINE)
        require(len(matches) == 1, 'Private mtg config must contain exactly one top-level quoted secret')
        text = matches[0]
    return parse_secret(text.strip())


def client_hello(key, hostname):
    """Let OpenSSL emit a well-formed ClientHello, then authenticate its random."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    outgoing = ssl.MemoryBIO()
    tls = context.wrap_bio(ssl.MemoryBIO(), outgoing, server_hostname=hostname)
    try:
        tls.do_handshake()
    except ssl.SSLWantReadError:
        pass
    hello = bytearray(outgoing.read())
    require(hello[:3] == b'\x16\x03\x01' and len(hello) == 5 + int.from_bytes(hello[3:5], 'big')
            and hello[5] == 1 and len(hello) > 75, 'OpenSSL did not produce a supported ClientHello')
    hello[RANDOM_OFFSET:RANDOM_OFFSET + 32] = bytes(32)
    digest = bytearray(hmac.digest(key, hello, 'sha256'))
    timestamp = struct.pack('<I', int(time.time()))
    for index, value in enumerate(timestamp):
        digest[28 + index] ^= value
    hello[RANDOM_OFFSET:RANDOM_OFFSET + 32] = digest
    session_length = hello[43]
    require(1 <= session_length <= 32, 'OpenSSL generated an unsupported TLS session ID')
    return bytes(hello), bytes(digest), bytes(hello[44:44 + session_length])


class Wire:
    def __init__(self, sock, deadline):
        self.sock, self.deadline = sock, deadline

    def timeout(self):
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, 'MTProto probe deadline exceeded')
        self.sock.settimeout(remaining)

    def read(self, count):
        require(0 <= count <= 65536, 'MTProto peer requested an oversized read')
        data = bytearray()
        while len(data) < count:
            self.timeout()
            chunk = self.sock.recv(count - len(data))
            require(bool(chunk), 'MTProto peer closed the stream')
            data.extend(chunk)
        return bytes(data)

    def send(self, data):
        self.timeout()
        self.sock.sendall(data)

    def record(self):
        header = self.read(5)
        length = int.from_bytes(header[3:], 'big')
        require(header[1:3] == b'\x03\x03' and 0 < length <= 18432,
                'Peer did not send a supported FakeTLS record')
        return header + self.read(length)


def authenticate_server(key, client_random, session, records):
    require(len(records) == 3 and records[0][0] == 22 and records[1] == b'\x14\x03\x03\x00\x01\x01'
            and records[2][0] == 23, 'Unexpected FakeTLS server handshake')
    packet = bytearray(b''.join(records))
    require(len(records[0]) >= 44 + len(session) and records[0][5] == 2
            and records[0][9:11] == b'\x03\x03' and records[0][43] == len(session)
            and hmac.compare_digest(records[0][44:44 + len(session)], session),
            'FakeTLS server session ID differs from the request')
    received = bytes(packet[RANDOM_OFFSET:RANDOM_OFFSET + 32])
    packet[RANDOM_OFFSET:RANDOM_OFFSET + 32] = bytes(32)
    expected = hmac.digest(key, client_random + packet, 'sha256')
    require(hmac.compare_digest(received, expected), 'FakeTLS server authentication failed')


class TLSRecords:
    def __init__(self, wire):
        self.wire, self.buffer = wire, bytearray()

    def read(self, count):
        while len(self.buffer) < count:
            record = self.wire.record()
            require(record[0] == 23, 'Unexpected FakeTLS record after the handshake')
            self.buffer.extend(record[5:])
            require(len(self.buffer) <= 65536, 'FakeTLS peer buffered too much data')
        result = bytes(self.buffer[:count])
        del self.buffer[:count]
        return result

    def send(self, data):
        require(len(data) <= 16379, 'FakeTLS probe record is too large')
        self.wire.send(b'\x17\x03\x03' + struct.pack('>H', len(data)) + data)


def obfuscated_transport(key, dc):
    while True:
        frame = bytearray(secrets.token_bytes(64))
        if frame[0] != 0xef and frame[:4] not in (b'HEAD', b'POST', b'GET ', b'OPTI',
                b'\x16\x03\x01\x02', b'\xdd' * 4, b'\xee' * 4) and any(frame[4:8]):
            break
    frame[56:60] = b'\xdd' * 4
    frame[60:62] = struct.pack('<h', dc)
    reverse = bytes(frame[8:56][::-1])
    send = AESCTR(hashlib.sha256(bytes(frame[8:40]) + key).digest(), bytes(frame[40:56]))
    receive = AESCTR(hashlib.sha256(reverse[:32] + key).digest(), reverse[32:])
    packet = bytearray(send.crypt(bytes(frame)))
    packet[8:56] = frame[8:56]
    return bytes(packet), send, receive


def request_packet(nonce):
    require(len(nonce) == 16, 'Invalid MTProto request nonce length')
    now = time.time_ns()
    message_id = ((now // 1_000_000_000) << 32) | (((now % 1_000_000_000) << 32) // 1_000_000_000)
    body = struct.pack('<I', REQ_PQ_MULTI) + nonce
    envelope = bytes(8) + struct.pack('<QI', message_id & ~3, len(body)) + body
    return struct.pack('<I', len(envelope)) + envelope


def validate_res_pq(reply, nonce):
    require(64 <= len(reply) <= 256 and reply[:8] == bytes(8), 'Invalid MTProto resPQ envelope')
    body_length = struct.unpack('<I', reply[16:20])[0]
    require(44 <= body_length <= len(reply) - 20 and 0 <= len(reply) - 20 - body_length <= 15,
            'Invalid MTProto resPQ body length')
    body = reply[20:20 + body_length]
    require(struct.unpack('<I', body[:4])[0] == RES_PQ and hmac.compare_digest(body[4:20], nonce),
            'Telegram resPQ did not match the request nonce')
    require(any(body[20:36]), 'Telegram resPQ has an empty server nonce')
    pq_length = body[36]
    require(1 <= pq_length <= 8 and 37 + pq_length <= len(body), 'Invalid Telegram resPQ pq value')
    pq = int.from_bytes(body[37:37 + pq_length], 'big')
    offset = 36 + ((1 + pq_length + 3) // 4) * 4
    require(pq > 1 and len(body) >= offset + 8 and struct.unpack('<I', body[offset:offset + 4])[0] == VECTOR,
            'Invalid Telegram resPQ fingerprints vector')
    count = struct.unpack('<I', body[offset + 4:offset + 8])[0]
    require(1 <= count <= 16 and len(body) == offset + 8 + 8 * count,
            'Invalid Telegram resPQ fingerprint count')
    return count


def probe(host, port, key, hostname, *, dc=2, timeout=15):
    require(1 <= abs(dc) <= 5 and 1 <= port <= 65535 and 1 <= timeout <= 60, 'Invalid probe destination or timeout')
    start = time.monotonic()
    stage, authenticated = 'tcp_connect', False
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            wire = Wire(sock, start + timeout)
            stage = 'client_hello'
            hello, random, session = client_hello(key, hostname)
            stage = 'fake_tls'
            wire.send(hello)
            authenticate_server(key, random, session, [wire.record() for _ in range(3)])
            authenticated = True
            handshake_ms = round((time.monotonic() - start) * 1000, 1)
            records = TLSRecords(wire)
            stage = 'crypto'
            packet, send, receive = obfuscated_transport(key, dc)
            try:
                nonce = secrets.token_bytes(16)
                stage = 'mtproto_rpc'
                wire.send(b'\x14\x03\x03\x00\x01\x01')
                records.send(packet + send.crypt(request_packet(nonce)))
                length = struct.unpack('<I', receive.crypt(records.read(4)))[0]
                require(64 <= length <= 256, 'MTProto peer sent an invalid response frame length')
                count = validate_res_pq(receive.crypt(records.read(length)), nonce)
            finally:
                send.close()
                receive.close()
    except (OSError, ValueError, AttributeError, ProbeError) as error:
        message = str(error) if type(error) is ProbeError else type(error).__name__
        wrapped = ProbeError(message)
        wrapped.stage, wrapped.fake_tls = stage, authenticated
        raise wrapped from None
    return {'passed': True, 'fake_tls': True, 'obfuscated2': True, 'nonce_verified': True, 'dc': dc,
            'rsa_fingerprints': count, 'handshake_ms': handshake_ms,
            'rpc_ms': round((time.monotonic() - start) * 1000 - handshake_ms, 1),
            'account_or_auth_key_created': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True)
    parser.add_argument('--port', required=True, type=int)
    parser.add_argument('--dc', type=int, default=2)
    parser.add_argument('--timeout', type=int, default=15)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--config', type=Path, help='Private mtg TOML config; secret is never printed')
    group.add_argument('--secret-file', type=Path, help='Private file containing only an ee secret')
    args = parser.parse_args()
    try:
        key, hostname = load_secret(args.config or args.secret_file, config=bool(args.config))
        print(json.dumps(probe(args.host, args.port, key, hostname, dc=args.dc, timeout=args.timeout)))
    except (OSError, ValueError, AttributeError, ProbeError) as error:
        # Socket/libcrypto/file exceptions can contain addresses or input data.
        message = str(error) if type(error) is ProbeError else type(error).__name__
        print(json.dumps({'passed': False, 'stage': getattr(error, 'stage', 'configuration'),
                          'fake_tls': getattr(error, 'fake_tls', False), 'error': message}))
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
