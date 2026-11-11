#!/usr/bin/env bash
set -euo pipefail
umask 077

stage=$1
config_dir=/etc/vpn-usage
mapping=$config_dir/devices.json
collector=/opt/vpn-usage/collector.py
dashboard_dir=/etc/vpn-monitoring/grafana/dashboards
textfile_dir=/var/lib/vpn-node/textfile
test -d "$dashboard_dir"
test -d "$textfile_dir"
systemctl is-active --quiet vpn-node-exporter.service
if [[ -f "$stage/payload/devices.json" ]]; then
  mapping=$stage/payload/devices.json
fi

python3 "$stage/vpn_usage_collector.py" --devices "$mapping" --output "$stage/vpn-usage-test.prom"
rm -f "$stage/vpn-usage-test.prom"

install -d -m 700 /opt/vpn-usage "$config_dir"
install -m 600 "$stage/vpn_usage_collector.py" "$collector.new"
mv -f "$collector.new" "$collector"
if [[ "$mapping" != "$config_dir/devices.json" ]]; then
  install -m 600 "$mapping" "$config_dir/devices.json.new"
  mv -f "$config_dir/devices.json.new" "$config_dir/devices.json"
fi

install -m 644 "$stage/payload/vpn-usage-collector.service" /etc/systemd/system/
install -m 644 "$stage/payload/vpn-usage-collector.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl start vpn-usage-collector.service
systemctl enable --now vpn-usage-collector.timer
test -s "$textfile_dir/vpn-usage.prom"

install -m 644 "$stage/payload/vpn-usage.json" "$dashboard_dir/vpn-usage.json.new"
mv -f "$dashboard_dir/vpn-usage.json.new" "$dashboard_dir/vpn-usage.json"
