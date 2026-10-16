#!/usr/bin/env python3
"""Upload existing local credentials to GitHub Secrets, without running CI."""
import argparse
import json
import re
import subprocess

from ci_environment import local_secrets


def gh(*args, data=None, capture=False):
    return subprocess.run(['gh', *args], input=data, check=True,
                          stdout=subprocess.PIPE if capture else subprocess.DEVNULL)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', default='Ja1rman/vpn')
    args = parser.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', args.repo):
        raise ValueError('Invalid repository name')
    # Read and validate EVERYTHING before making the first GitHub write.
    values, username = local_secrets()
    endpoint = 'repos/' + args.repo + '/environments/production'
    gh('api', '--method', 'PUT', endpoint, '--input', '-',
       data=json.dumps({'deployment_branch_policy': {
           'protected_branches': False, 'custom_branch_policies': True}}).encode())
    policies = json.loads(gh('api', endpoint + '/deployment-branch-policies', capture=True).stdout)
    if not any(p['name'] == 'main' and p.get('type', 'branch') == 'branch'
               for p in policies['branch_policies']):
        gh('api', '--method', 'POST', endpoint + '/deployment-branch-policies',
           '--input', '-', data=json.dumps({'name': 'main', 'type': 'branch'}).encode())
    for name, value in values.items():
        gh('secret', 'set', name, '--repo', args.repo, '--env', 'production', data=value.encode())
        print('Saved production Secret: ' + name)
    gh('variable', 'set', 'VPN_MONITORING_USERNAME', '--repo', args.repo, data=username.encode())
    # Always leave production disabled after synchronizing credentials.
    gh('variable', 'set', 'VPN_DEPLOY_ENABLED', '--repo', args.repo, data=b'false')
    print('Repository variable VPN_DEPLOY_ENABLED=false. No workflow was dispatched.')


if __name__ == '__main__':
    main()
