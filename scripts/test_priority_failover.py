#!/usr/bin/env python3
"""Isolated three-exit primary/backup TCP+UDP test. Never stops real services."""
import http.server
import json
import os
from pathlib import Path
import secrets
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time
import uuid

from priority_pool import build_priority_chain

XRAY = '/opt/vpn-balancer/xray'
ENV = dict(os.environ, XRAY_LOCATION_ASSET='/opt/vpn-balancer')


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def udp_echo(port):
    nonce = secrets.token_bytes(12)
    with socket.create_connection(('127.0.0.1', port), timeout=5) as control:
        control.sendall(b'\x05\x01\x00')
        if control.recv(2) != b'\x05\x00':
            raise RuntimeError('SOCKS greeting failed')
        control.sendall(b'\x05\x03\x00\x01' + socket.inet_aton('127.0.0.1') + b'\x00\x00')
        reply = control.recv(262)
        if len(reply) < 10 or reply[1:4] != b'\x00\x00\x01':
            raise RuntimeError('UDP ASSOCIATE failed')
        address = socket.inet_ntoa(reply[4:8])
        relay = ('127.0.0.1' if address == '0.0.0.0' else address, struct.unpack('!H', reply[8:10])[0])
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.settimeout(5)
            udp.sendto(b'\x00\x00\x00\x01' + socket.inet_aton('198.18.0.1') + struct.pack('!H', 53) + nonce, relay)
            result, _ = udp.recvfrom(2048)
            if not result.endswith(b'|' + nonce):
                raise RuntimeError('UDP echo payload corrupted')
            return result[-len(nonce)-2:-len(nonce)-1].decode()


def main():
    os.umask(0o077)
    processes, servers = [], []
    with tempfile.TemporaryDirectory(prefix='vpn-priority-test-') as tmp:
        folder = Path(tmp)

        def start(name, config):
            path = folder / (name + '.json')
            path.write_text(json.dumps(config))
            with (folder / (name + '.log')).open('ab') as log:
                process = subprocess.Popen([XRAY, 'run', '-config', str(path)], env=ENV, stdout=log, stderr=log)
            processes.append(process)
            return process

        def backend(identity):
            class HTTP(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    body = identity.encode()
                    self.send_response(204 if self.path == '/health' else 200)
                    self.send_header('Content-Length', '0' if self.path == '/health' else str(len(body)))
                    self.end_headers()
                    if self.path != '/health':
                        self.wfile.write(body)

                def log_message(self, *args):
                    pass

            class UDP(socketserver.BaseRequestHandler):
                def handle(self):
                    payload, sock = self.request
                    sock.sendto(identity.encode() + b'|' + payload, self.client_address)

            http_server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), HTTP)
            udp = socketserver.ThreadingUDPServer(('127.0.0.1', http_server.server_port), UDP)
            for server in [http_server, udp]:
                server.daemon_threads = True
                threading.Thread(target=server.serve_forever, daemon=True).start()
                servers.append(server)
            return http_server.server_port

        uid = str(uuid.uuid4())
        exits, exit_configs, outbounds = {}, {}, []
        try:
            for name in ['a', 'b', 'c']:
                port, target = free_port(), backend(name)
                config = {'log': {'loglevel': 'error'}, 'inbounds': [
                    {'listen': '127.0.0.1', 'port': port, 'protocol': 'vless',
                     'settings': {'clients': [{'id': uid}], 'decryption': 'none'}}],
                    'outbounds': [{'protocol': 'freedom', 'settings': {
                        'redirect': '127.0.0.1:' + str(target),
                        # New cores block private targets on VLESS exits by
                        # default. Only these disposable fixtures allow their
                        # own loopback echo backend; production is unchanged.
                        'finalRules': [{'action': 'allow', 'ip': ['127.0.0.1/32']}]}}]}
                exit_configs[name] = config
                exits[name] = start(name, config)
                outbounds.append({'tag': 'pool-test-' + name, 'protocol': 'vless',
                                  'settings': {'address': '127.0.0.1', 'port': port, 'id': uid, 'encryption': 'none'}})
            bridges, rules, balancers = build_priority_chain([o['tag'] for o in outbounds])
            socks_port, api_port = free_port(), free_port()
            pool = {'log': {'loglevel': 'error'}, 'api': {'tag': 'api', 'services': ['RoutingService']},
                    'inbounds': [{'tag': 'socks', 'listen': '127.0.0.1', 'port': socks_port, 'protocol': 'socks',
                                  'settings': {'auth': 'noauth', 'udp': True}},
                                 {'tag': 'api', 'listen': '127.0.0.1', 'port': api_port, 'protocol': 'tunnel',
                                  'settings': {'address': '127.0.0.1'}}],
                    'outbounds': [{'tag': 'blocked', 'protocol': 'blackhole'}] + outbounds + bridges,
                    'routing': {'rules': [{'type': 'field', 'inboundTag': ['api'], 'outboundTag': 'api'},
                                          {'type': 'field', 'inboundTag': ['socks'], 'balancerTag': 'vpn-pool'}] + rules,
                                'balancers': balancers},
                    'observatory': {'subjectSelector': ['pool-test-'], 'probeUrl': 'http://fixture.invalid/health',
                                    'probeInterval': '1s', 'enableConcurrency': True}}
            start('pool', pool)

            def request():
                result = subprocess.run(['curl', '--fail', '--silent', '--max-time', '3', '--proxy',
                                         'socks5h://127.0.0.1:' + str(socks_port), 'http://fixture.invalid/identity'],
                                        capture_output=True)
                last_request.update(code=result.returncode,stdout=result.stdout.decode().strip(),stderr=result.stderr.decode().strip())
                return result.stdout.decode().strip() if result.returncode == 0 else None

            last_request = {}

            def expect(identity):
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    if request() == identity:
                        answers = [request() for _ in range(8)]
                        if answers == [identity] * 8 and udp_echo(socks_port) == identity:
                            return
                    time.sleep(0.5)
                raise RuntimeError('Priority selection did not converge to ' + identity + ': ' + json.dumps(last_request))

            expect('a')
            exits['a'].terminate(); exits['a'].wait(timeout=5)
            expect('b')
            exits['b'].terminate(); exits['b'].wait(timeout=5)
            expect('c')
            exits['a'] = start('a-recovered', exit_configs['a'])
            expect('a')
            exits['a'].terminate(); exits['a'].wait(timeout=5)
            exits['c'].terminate(); exits['c'].wait(timeout=5)
            time.sleep(2)
            if request() is not None:
                raise RuntimeError('All exits down but traffic escaped the blackhole')
            print(json.dumps({'isolated_primary_backup': 'passed', 'all_healthy': 'only_a',
                              'a_down': 'only_b', 'a_and_b_down': 'only_c', 'a_recovered': 'only_a',
                              'tcp_udp_at_each_stage': 'passed', 'all_down': 'blocked',
                              'production_services_untouched': True}))
        except Exception:
            for path in folder.glob('*.log'):
                print(path.name + ': ' + path.read_text()[-1800:])
            raise
        finally:
            for process in reversed(processes):
                if process.poll() is None:
                    process.terminate()
            for process in processes:
                process.wait(timeout=10)
            for server in servers:
                server.shutdown()
                server.server_close()


if __name__ == '__main__':
    main()
