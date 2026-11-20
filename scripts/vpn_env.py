"""Resolve deployment endpoints from the environment and private local files."""
import json
import os
from pathlib import Path
import re


TOKEN = re.compile(r'\$\{(VPN_[A-Z0-9_]+)\}')
ENDPOINT_NAME = re.compile(r'VPN_[A-Z0-9_]+_(?:ADDRESS|IP|PORT|PORTS|URL)(?:_[A-Z])?')


def environment_paths():
    return [Path('/etc/vpn-infra/network-env.json'),
             Path(__file__).resolve().parents[1] / '.local/network-env.json',
             Path(__file__).with_name('vpn.env.json')]


def configured_values():
    result = {}
    for path in environment_paths():
        try:
            source = path.read_text()
        except FileNotFoundError:
            continue
        except PermissionError:
            if path == Path('/etc/vpn-infra/network-env.json'):
                # Dedicated service users load their own adjacent runtime file.
                continue
            raise
        else:
            values = json.loads(source)
            if not isinstance(values, dict):
                raise ValueError('The private network environment must be a JSON object')
            result.update(values)
    if os.environ.get('VPN_ENDPOINTS_JSON'):
        values = json.loads(os.environ['VPN_ENDPOINTS_JSON'])
        if not isinstance(values, dict):
            raise ValueError('VPN_ENDPOINTS_JSON must be a JSON object')
        result.update(values)
    names = set(result) | {name for name in os.environ if ENDPOINT_NAME.fullmatch(name)}
    for name in names:
        if os.environ.get(name):
            result[name] = os.environ[name]
    return result


def value(name):
    if not re.fullmatch(r'VPN_[A-Z0-9_]+', name):
        raise ValueError('Invalid deployment environment variable name')
    result = os.environ.get(name) or configured_values().get(name)
    if result is None or result == '':
        raise ValueError('Set the required deployment environment variable ' + name)
    return result


def env(name):
    result = value(name)
    if isinstance(result, (list, dict)):
        return json.dumps(result)
    return str(result)


def port(name):
    result = value(name)
    if isinstance(result, bool) or not str(result).isdecimal() or not 1 <= int(result) <= 65535:
        raise ValueError('Invalid network port in ' + name)
    return int(result)


def expand(text):
    return TOKEN.sub(lambda match: env(match[1]), text)


def resolve(item):
    if isinstance(item, dict):
        return {expand(key): resolve(child) for key, child in item.items()}
    if isinstance(item, list):
        return [resolve(child) for child in item]
    if not isinstance(item, str):
        return item
    match = TOKEN.fullmatch(item)
    if match:
        name = match[1]
        if name.endswith('_PORT'):
            return port(name)
        result = value(name)
        if name.endswith('_PORTS') and isinstance(result, str):
            result = json.loads(result)
        return result
    return expand(item)


def load_json(path):
    return resolve(json.loads(Path(path).read_text()))
