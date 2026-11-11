import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('install_grafana_https', ROOT / 'scripts/install_grafana_https.py')
https = importlib.util.module_from_spec(spec)
spec.loader.exec_module(https)


class GrafanaHTTPSTest(unittest.TestCase):
    def test_nginx_template_accepts_only_ipv4_addresses(self):
        template = ROOT / 'monitoring/nginx-grafana-https.conf'
        rendered = https.render(template, '192.0.2.10')
        self.assertNotIn('__GRAFANA_PUBLIC_IP__', rendered)
        self.assertIn("'http://192.0.2.10/grafana/' 'https://192.0.2.10/grafana/'", rendered)
        with self.assertRaises(ValueError):
            https.render(template, '192.0.2.10; listen 80')

    def container(self, label=True, pid=31):
        return {'Id': 'sidecar-id', 'State': {'Running': True, 'Pid': pid},
                'Config': {'Labels': {https.LABEL: 'owned'} if label else {}}}

    def test_same_certificate_does_not_reload_nginx(self):
        with patch.object(https, 'inspect_container', return_value=self.container()), \
                patch.object(https, 'source_fingerprint', return_value='same'), \
                patch.object(https, 'served_fingerprint', return_value='same'), \
                patch.object(https, 'command') as command:
            result = https.sync('192.0.2.10')
        self.assertEqual(result['grafana_https_certificate'], 'current; no reload')
        command.assert_not_called()

    def test_rotation_validates_then_reloads_only_managed_container(self):
        with patch.object(https, 'inspect_container', return_value=self.container()), \
                patch.object(https, 'source_fingerprint', return_value='new'), \
                patch.object(https, 'served_fingerprint', side_effect=['old', 'new']), \
                patch.object(https, 'command') as command:
            result = https.sync('192.0.2.10')
        self.assertTrue(result['pid_unchanged'])
        calls = [entry.args for entry in command.call_args_list]
        self.assertEqual(calls[0], ('docker', 'exec', 'sidecar-id', 'nginx', '-t', '-c', str(https.CONFIG)))
        self.assertEqual(calls[1], ('docker', 'kill', '--signal=HUP', 'sidecar-id'))

    def test_unmanaged_container_is_never_reloaded(self):
        with patch.object(https, 'inspect_container', return_value=self.container(label=False)), \
                patch.object(https, 'command') as command:
            with self.assertRaises(RuntimeError):
                https.sync('192.0.2.10')
        command.assert_not_called()


if __name__ == '__main__':
    unittest.main()
