#!/usr/bin/env bash
set -euo pipefail
stage=$1
install -d -m 755 /etc/vpn-monitoring/grafana/dashboards
install -m 644 "$stage"/grafana/dashboards/*.json /etc/vpn-monitoring/grafana/dashboards/
install -m 640 -o root -g 472 "$stage/grafana/admin-user" /etc/vpn-monitoring/grafana/admin-user
install -m 640 -o root -g 472 "$stage/grafana/admin-password" /etc/vpn-monitoring/grafana/admin-password
# Keep the inode: nginx mounts this file directly, rather than its parent directory.
cat "$stage/monitoring.htpasswd" > /etc/vpn-monitoring/monitoring.htpasswd
chmod 644 /etc/vpn-monitoring/monitoring.htpasswd
docker exec vpn-monitoring-web-1 nginx -t
docker exec vpn-monitoring-web-1 nginx -s reload
echo 'Access files updated; Grafana discovers the dashboards within 30 seconds.'
