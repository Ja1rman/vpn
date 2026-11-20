#!/usr/bin/env python3
"""Arm a guarded main-Xray Telegram hairpin update; commit only after external proof."""
import argparse
import copy
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time

import enable_failover_variant as core
import telegram_local_routes as routes
import vpn_env


PREFIX = 'telegram-local-'
TIMEOUT = 180
PROOF_KEYS = ('native_mtp', 'native_socks', 'native_dd')
SNAPSHOTS = ('runtime-before.json', 'runtime-after.json', 'template-before.json',
             'template-after.json', 'routing-before.json', 'routing-after.json', 'baseline.json')


def need(condition, message):
    if not condition:
        raise RuntimeError(message)


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def inbound_fingerprint(inbounds):
    """Canonicalize only API map enumeration; preserve every handler's exact content."""
    need(isinstance(inbounds, list), 'Live API returned an invalid inbound collection')
    values = copy.deepcopy(inbounds)
    tags = [item.get('tag') for item in values if isinstance(item, dict)]
    need(len(tags) == len(values) and all(isinstance(tag, str) and tag for tag in tags)
         and len(tags) == len(set(tags)), 'Live API has missing or duplicate inbound identities')
    values.sort(key=lambda item: item['tag'])
    return fingerprint(values)


def write_private(path, value):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())


def private_bytes(path):
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o077,
         'Expected a private root-owned transaction file')
    return path.read_bytes()


def transaction_folder(folder):
    need(not folder.is_symlink(), 'Transaction directory must not be a symlink')
    folder = folder.resolve(strict=True)
    info = folder.lstat()
    need(folder.parent == core.BACKUPS.resolve() and folder.name.startswith(PREFIX)
         and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700,
         'Expected a root-private local Telegram transaction directory')
    return folder


@contextmanager
def locked():
    # Serialize with the existing main-Xray route updater, including watchdogs.
    with core.LOCK.open('a') as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        yield


def api_snapshot(server=None):
    def query(command):
        if server is None:
            return json.loads(core.api(command))
        return json.loads(core.command([str(core.XRAY), 'api', command,
                                         '--server=' + server, '--timeout=6']))
    outbounds = query('lso').get('outbounds', [])
    mapping = {item['tag']: fingerprint(item) for item in outbounds}
    need(len(mapping) == len(outbounds), 'Live API has duplicate outbound identities')
    inbounds = query('lsi').get('inbounds', [])
    rules = query('lsrules').get('rules', [])
    return {'outbounds': mapping, 'inbounds': inbound_fingerprint(inbounds), 'rules': fingerprint(rules)}


def compiler_config(config, endpoint):
    # Never inherit metrics/reverse/observer apps: they can bind production
    # sockets or initiate traffic even when every normal input was removed.
    return {'inbounds': [], 'log': {'loglevel': 'warning', 'access': 'none'},
            'outbounds': copy.deepcopy(config['outbounds']), 'routing': copy.deepcopy(config['routing']),
            'api': {'tag': 'api', 'listen': str(endpoint),
                    'services': ['HandlerService', 'RoutingService']}}


def compile_candidate(config):
    """Normalize new handlers/rules in a private Unix-API core with no TCP inputs."""
    with tempfile.TemporaryDirectory(prefix='telegram-local-compile-') as tmp:
        directory = Path(tmp)
        directory.chmod(0o700)
        endpoint = directory / 'api.sock'
        candidate = compiler_config(config, endpoint)
        path = directory / 'config.json'
        write_private(path, core.json_bytes(candidate))
        with (directory / 'xray.log').open('wb') as log:
            process = subprocess.Popen([str(core.XRAY), 'run', '-config', str(path)],
                                       stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                       env=dict(os.environ, XRAY_LOCATION_ASSET=str(core.XRAY.parent)),
                                       start_new_session=True)
        try:
            for _ in range(60):
                need(process.poll() is None, 'The private candidate compiler exited')
                if endpoint.exists():
                    break
                time.sleep(.1)
            else:
                raise RuntimeError('The private candidate compiler API did not start')
            result = api_snapshot('unix://' + str(endpoint))
            need(set(routes.TAGS) <= result['outbounds'].keys(), 'Candidate handlers did not compile')
            return {tag: result['outbounds'][tag] for tag in routes.TAGS}, result['rules']
        except BaseException:
            core.BACKUPS.mkdir(mode=0o700, parents=True, exist_ok=True)
            diagnostic = core.BACKUPS / ('telegram-compile-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
            diagnostic.mkdir(mode=0o700)
            write_private(diagnostic / 'xray.log', (directory / 'xray.log').read_bytes())
            raise RuntimeError('Private candidate compiler failed; diagnostic log: ' + str(diagnostic / 'xray.log')) from None
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def stage_watchdog(folder):
    for module in (sys.modules[__name__], core, routes, vpn_env):
        source = Path(module.__file__).resolve()
        write_private(folder / source.name, source.read_bytes())
    write_private(folder / 'vpn.env.json', core.json_bytes(vpn_env.configured_values()))


def start_watchdog(folder):
    with (folder / 'watchdog.log').open('ab') as log:
        process = subprocess.Popen([sys.executable, '-B', str(folder / 'enable_telegram_local.py'),
                                    'watchdog', str(folder)], stdin=subprocess.DEVNULL,
                                   stdout=log, stderr=log, start_new_session=True)
    for _ in range(50):
        need(process.poll() is None, 'The independent rollback watchdog did not start')
        if (folder / 'watchdog-ready').exists():
            ready = json.loads(private_bytes(folder / 'watchdog-ready'))
            need(ready.get('pid') == process.pid, 'Unexpected rollback watchdog identity')
            return
        time.sleep(.1)
    raise RuntimeError('The independent rollback watchdog did not become ready')


def load_transaction(folder):
    old, new, template_old, template_new = (private_bytes(folder / name) for name in SNAPSHOTS[:4])
    baseline = json.loads(private_bytes(folder / 'baseline.json'))
    runtime, template = json.loads(old), json.loads(template_old)
    expected_runtime, expected_template = routes.candidates(runtime, template)
    need(json.loads(new) == expected_runtime and json.loads(template_new) == expected_template
         and expected_runtime != runtime, 'Transaction snapshots do not describe the narrow Telegram change')
    added = set(baseline['added'])
    old_tags = {outbound['tag'] for outbound in runtime['outbounds']}
    new_tags = {outbound['tag'] for outbound in expected_runtime['outbounds']}
    need(bool(added) and added <= set(routes.TAGS) and added == new_tags-old_tags
         and not added.intersection(baseline['before_outbounds'])
         and baseline['after_outbounds'] == baseline['before_outbounds'] | baseline['added'],
         'Transaction contains unexpected handler changes')
    return old, new, template_old, template_new, baseline


def guard(folder, *, complete=False):
    old, new, template_old, template_new, baseline = load_transaction(folder)
    need(core.runtime_identity() == baseline['process'], 'Main Xray process changed; transaction refused')
    current, template = core.CONFIG.read_bytes(), core.read_template()
    live = api_snapshot()
    need(live['inbounds'] == baseline['inbounds'], 'Main live input handlers changed; transaction refused')
    if complete:
        need(current == new and template == template_new and live['rules'] == baseline['after_rules']
             and live['outbounds'] == baseline['after_outbounds'],
             'Transaction is not the exact expected applied state')
        core.pin_live(json.loads(new))
    else:
        need(current in (old, new) and template in (template_old, template_new)
             and live['rules'] in (baseline['before_rules'], baseline['after_rules'])
             and baseline['before_outbounds'].items() <= live['outbounds'].items()
             <= baseline['after_outbounds'].items(),
             'Concurrent runtime, template or API changes; automatic rollback refused')
    return old, new, template_old, template_new, baseline, live


def rollback(folder, *, force=False):
    if (folder / 'rolled-back').exists():
        return {'rolled_back': True, 'already_done': True}
    if (folder / 'committed').exists() and not force:
        return {'committed': True}
    old, new, template_old, template_new, baseline, live = guard(folder)
    if live['rules'] == baseline['after_rules']:
        core.api('adrules', folder / 'routing-before.json')
    need(api_snapshot()['rules'] == baseline['before_rules'], 'Previous live routing was not restored')
    current_template = core.read_template()
    if current_template == template_new:
        core.write_template(template_new, template_old)
    else:
        need(current_template == template_old, 'Concurrent template change during rollback')
    current = core.CONFIG.read_bytes()
    if current == new:
        core.write_runtime(new, old)
    else:
        need(current == old, 'Concurrent runtime change during rollback')
    # Only handlers first introduced by this transaction may be removed.
    current_live = api_snapshot()
    need(current_live['rules'] == baseline['before_rules'] and current_live['inbounds'] == baseline['inbounds']
         and baseline['before_outbounds'].items() <= current_live['outbounds'].items()
         <= baseline['after_outbounds'].items(), 'Concurrent API change during rollback')
    for tag in baseline['added']:
        if tag in current_live['outbounds']:
            need(current_live['outbounds'][tag] == baseline['added'][tag], 'A new Telegram handler was edited')
            core.api('rmo', tag)
    final = api_snapshot()
    need(final['outbounds'] == baseline['before_outbounds'] and final['rules'] == baseline['before_rules']
         and final['inbounds'] == baseline['inbounds'] and core.runtime_identity() == baseline['process']
         and core.CONFIG.read_bytes() == old and core.read_template() == template_old,
         'The previous main-Xray state could not be verified')
    core.pin_live(json.loads(old))
    write_private(folder / 'rolled-back', b'Only owned Telegram routes/handlers were removed; no restart\n')
    return {'rolled_back': True, 'backup': str(folder)}


def matching_pending(current, template):
    matches = []
    for path in core.BACKUPS.glob(PREFIX + '*'):
        if not path.is_dir() or (path / 'committed').exists() or (path / 'rolled-back').exists():
            continue
        folder = transaction_folder(path)
        if not (folder / 'baseline.json').is_file() or not (folder / 'watchdog-ready').is_file():
            # Preflight failures cannot have changed live state: the API phase
            # starts only after the durable baseline and watchdog-ready barrier.
            continue
        if private_bytes(folder / 'runtime-after.json') == current and private_bytes(folder / 'template-after.json') == template:
            guard(folder, complete=True)
            matches.append(folder)
    need(len(matches) <= 1, 'Multiple uncommitted Telegram transactions match this state')
    return matches[0] if matches else None


def apply():
    old, template_old = core.CONFIG.read_bytes(), core.read_template()
    runtime, template = json.loads(old), json.loads(template_old)
    desired, desired_template = routes.candidates(runtime, template)
    process = core.runtime_identity()
    core.pin_live(runtime)
    before = api_snapshot()
    expected_owned, expected_rules = compile_candidate(desired)
    need(all(before['outbounds'][tag] == digest for tag, digest in expected_owned.items()
             if tag in before['outbounds']), 'An existing local Telegram handler differs from the candidate')
    if desired == runtime and desired_template == template:
        need(all(before['outbounds'].get(tag) == digest for tag, digest in expected_owned.items())
             and before['rules'] == expected_rules, 'Installed Telegram handlers differ from the candidate')
        need(core.runtime_identity() == process and core.CONFIG.read_bytes() == old
             and core.read_template() == template_old and api_snapshot() == before,
             'Main Xray changed during the no-op check')
        pending = matching_pending(old, template_old)
        return {'already_configured': True, 'armed': bool(pending), 'backup': str(pending) if pending else None}
    added = {tag: digest for tag, digest in expected_owned.items() if tag not in before['outbounds']}
    need(bool(added) and set(added) <= set(routes.TAGS), 'The update has no new owned Telegram handler')
    core.BACKUPS.mkdir(mode=0o700, parents=True, exist_ok=True)
    folder = core.BACKUPS / (PREFIX + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
    folder.mkdir(mode=0o700)
    new, template_new = core.json_bytes(desired), core.json_bytes(desired_template)
    for name, contents in {'runtime-before.json': old, 'runtime-after.json': new,
                           'template-before.json': template_old, 'template-after.json': template_new,
                           'routing-before.json': core.json_bytes({'routing': runtime['routing']}),
                           'routing-after.json': core.json_bytes({'routing': desired['routing']}),
                           'outbounds.json': core.json_bytes({'outbounds': [outbound for outbound in routes.expected_outbounds()
                                                                          if outbound['tag'] in added]})}.items():
        write_private(folder / name, contents)
    core.command([str(core.XRAY), 'run', '-test', '-config', str(folder / 'runtime-after.json')])
    need(core.runtime_identity() == process and core.CONFIG.read_bytes() == old
         and core.read_template() == template_old and api_snapshot() == before,
         'Main Xray changed during transaction preflight')
    core.pin_live(runtime)
    baseline = {'process': process, 'before_outbounds': before['outbounds'], 'added': added,
                'after_outbounds': before['outbounds'] | added, 'inbounds': before['inbounds'],
                'before_rules': before['rules'], 'after_rules': expected_rules, 'deadline': time.time()+TIMEOUT}
    write_private(folder / 'baseline.json', core.json_bytes(baseline))
    stage_watchdog(folder)
    start_watchdog(folder)
    try:
        core.api('ado', folder / 'outbounds.json')
        interim = api_snapshot()
        need(interim == dict(before, outbounds=baseline['after_outbounds'])
             and core.runtime_identity() == process, 'Unexpected API change after adding Telegram handlers')
        need(core.CONFIG.read_bytes() == old and core.read_template() == template_old,
             'Main files changed before the routing switch')
        core.api('adrules', folder / 'routing-after.json')
        observed = api_snapshot()
        need(observed == {'outbounds': baseline['after_outbounds'], 'inbounds': before['inbounds'],
                          'rules': expected_rules} and core.runtime_identity() == process,
             'Live Telegram routing differs from the validated candidate')
        core.write_template(template_old, template_new)
        core.write_runtime(old, new)
        guard(folder, complete=True)
        write_private(folder / 'armed', b'External native Telegram proof is required before commit\n')
    except BaseException:
        rollback(folder)
        raise
    return {'armed': True, 'backup': str(folder), 'rollback_after_seconds': TIMEOUT,
            'external_proof_required': list(PROOF_KEYS)}


def commit(folder, proof):
    need(isinstance(proof, dict) and all(proof.get(key) is True for key in PROOF_KEYS),
         'Commit requires successful external native MTProto, SOCKS and DD proof')
    need(not (folder / 'rolled-back').exists() and (folder / 'armed').exists(), 'Transaction is not armed')
    if 'transaction' in proof:
        need(proof['transaction'] == folder.name, 'External proof belongs to another transaction')
    *_, baseline, _live = guard(folder, complete=True)
    if not (folder / 'committed').exists():
        need(time.time() < baseline['deadline'], 'The external proof arrived after the rollback deadline')
        # Only safe booleans are retained; never persist arbitrary caller content.
        write_private(folder / 'external-proof.json', core.json_bytes({key: True for key in PROOF_KEYS}))
        write_private(folder / 'committed', b'External native MTProto, SOCKS and DD verified; main process unchanged\n')
    return {'committed': True, 'backup': str(folder)}


def watchdog(folder):
    baseline = json.loads(private_bytes(folder / 'baseline.json'))
    write_private(folder / 'watchdog-ready', core.json_bytes({'pid': os.getpid()}))
    while time.time() < baseline['deadline']:
        if (folder / 'committed').exists() or (folder / 'rolled-back').exists():
            return
        time.sleep(min(1, max(0, baseline['deadline']-time.time())))
    with locked():
        rollback(folder)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest='action', required=True)
    planner = actions.add_parser('plan')
    planner.add_argument('runtime', type=Path)
    planner.add_argument('template', type=Path)
    actions.add_parser('apply')
    for action in ('commit', 'rollback', 'watchdog'):
        actions.add_parser(action).add_argument('backup', type=Path)
    args = parser.parse_args()
    try:
        if args.action == 'plan':
            old, template = json.loads(args.runtime.read_bytes()), json.loads(args.template.read_bytes())
            desired, _ = routes.candidates(old, template)
            print(json.dumps({'already_configured': desired == old, 'new_handlers': list(routes.TAGS),
                              'vpn_inputs_unchanged': desired['inbounds'] == old['inbounds']}))
            return
        need(os.geteuid() == 0 and sys.platform.startswith('linux'), 'Live actions require root on the entry server')
        if args.action == 'watchdog':
            watchdog(transaction_folder(args.backup))
            return
        proof = None
        if args.action == 'commit':
            raw = sys.stdin.buffer.read(65537)
            need(len(raw) <= 65536, 'External proof packet is too large')
            proof = json.loads(raw)
        with locked():
            if args.action == 'apply':
                result = apply()
            else:
                folder = transaction_folder(args.backup)
                result = commit(folder, proof) if args.action == 'commit' else rollback(folder, force=True)
        print(json.dumps(result))
    except (OSError, RuntimeError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        parser.exit(1, 'enable-telegram-local: ' + (str(exc) if type(exc) is RuntimeError else type(exc).__name__) + '\n')


if __name__ == '__main__':
    main()
