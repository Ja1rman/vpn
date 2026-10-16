#!/usr/bin/env bash
set -euo pipefail
stage=$1
command -v docker >/dev/null
docker compose version
install -d -m 755 /etc/vpn-monitoring
cp -R "$stage/." /etc/vpn-monitoring/
find /etc/vpn-monitoring -type d -exec chmod 755 {} +
find /etc/vpn-monitoring -type f \
  ! -path /etc/vpn-monitoring/alertmanager/alertmanager.yml \
  ! -path /etc/vpn-monitoring/tls/client.key \
  ! -path /etc/vpn-monitoring/grafana/admin-password \
  ! -path /etc/vpn-monitoring/grafana/admin-user \
  -exec chmod 644 {} +
chown root:65534 /etc/vpn-monitoring/alertmanager/alertmanager.yml
chmod 640 /etc/vpn-monitoring/alertmanager/alertmanager.yml
chown root:65534 /etc/vpn-monitoring/tls/client.key
chmod 640 /etc/vpn-monitoring/tls/client.key
chown root:472 /etc/vpn-monitoring/grafana/admin-password
chmod 640 /etc/vpn-monitoring/grafana/admin-password
chown root:472 /etc/vpn-monitoring/grafana/admin-user
chmod 640 /etc/vpn-monitoring/grafana/admin-user
cd /etc/vpn-monitoring
docker compose config --quiet
docker compose pull --quiet
docker compose run --rm --no-deps --entrypoint /bin/promtool prometheus check config /etc/vpn-monitoring/prometheus/prometheus.yml
docker compose run --rm --no-deps --entrypoint /bin/amtool alertmanager check-config /etc/vpn-monitoring/alertmanager/alertmanager.yml
docker compose run --rm --no-deps web -t
docker compose up -d --remove-orphans
docker compose ps
