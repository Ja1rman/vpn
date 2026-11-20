#!/usr/bin/env python3
"""Build the checksum-pinned official Telegram WEB relay in private staging."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import tarfile
import tempfile

from install_web_proxy import SOURCE_COMMIT, SOURCE_SHA256, require


ROOT = Path(__file__).resolve().parents[1]


def source_files(archive):
    info = archive.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_size <= 32 * 1024 * 1024,
            'Expected a bounded regular official WEB source archive')
    raw = archive.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == SOURCE_SHA256, 'Official WEB source SHA256 mismatch')
    prefix = 'tproxy-server-' + SOURCE_COMMIT
    result = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as source:
        for member in source:
            name = PurePosixPath(member.name)
            require(name.parts and name.parts[0] == prefix and not name.is_absolute()
                    and all(part not in ('', '.', '..') for part in name.parts),
                    'Unsafe official WEB source archive path')
            require(member.isdir() or member.isfile(), 'Links and special WEB source members are refused')
            if member.isdir():
                continue
            relative = Path(*name.parts[1:])
            total += member.size
            require(0 <= member.size <= 8 * 1024 * 1024 and total <= 32 * 1024 * 1024
                    and relative not in result, 'Official WEB source archive exceeds bounds')
            content = source.extractfile(member)
            require(content is not None, 'Unreadable official WEB source member')
            result[relative] = content.read()
    require(Path('go.mod') in result and Path('go.sum') in result
            and Path('cmd/tproxy-server/main.go') in result, 'Incomplete official WEB source archive')
    return result


def command(arguments, directory, environment):
    result = subprocess.run(arguments, cwd=directory, env=environment, capture_output=True, timeout=180)
    require(result.returncode == 0, 'Pinned official WEB relay build or tests failed')


def build(archive, output):
    files = source_files(archive)
    private = ROOT / '.local/web-proxy'
    private.mkdir(parents=True, mode=0o700, exist_ok=True)
    environment = dict(os.environ, GOCACHE=str(private / 'build-cache'),
                       GOMODCACHE=str(private / 'modules'), GOMAXPROCS='2')
    output = output.resolve()
    output.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    require(not output.exists() and not output.is_symlink(), 'Refusing to replace an existing WEB executable')
    with tempfile.TemporaryDirectory(prefix='build-', dir=private) as temporary:
        folder = Path(temporary)
        for relative, data in files.items():
            target = folder / relative
            target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            target.write_bytes(data)
        command(['go', 'test', '-mod=readonly', '-p', '2', './...'], folder, environment)
        candidate = folder / 'tproxy-server'
        command(['go', 'build', '-mod=readonly', '-p', '2', '-trimpath', '-o', str(candidate),
                 './cmd/tproxy-server'], folder,
                dict(environment, GOOS='linux', GOARCH='amd64', CGO_ENABLED='0'))
        binary = candidate.read_bytes()
        require(binary[:6] == b'\x7fELF\x02\x01' and binary[18:20] == b'\x3e\x00',
                'Expected a Linux amd64 WEB executable')
        with output.open('xb') as stream:
            os.fchmod(stream.fileno(), 0o700)
            stream.write(binary)
    return {'source_commit': SOURCE_COMMIT, 'source_sha256': SOURCE_SHA256,
            'binary_sha256': hashlib.sha256(binary).hexdigest(), 'upstream_tests': 'passed'}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(build(args.archive, args.output)))
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        detail = str(error) if type(error) is RuntimeError else type(error).__name__
        parser.exit(1, 'build-web-proxy: ' + detail + '\n')


if __name__ == '__main__':
    main()
