#!/usr/bin/env bash
set -euo pipefail
umask 027
stage=$1
listen_address=$2
version=$3
checksum=$4
test "$(uname -m)" = x86_64 || { echo 'Only x86_64 is supported by this release lock'; exit 1; }
getent group vpn-node >/dev/null || groupadd --system vpn-node
id vpn-node >/dev/null 2>&1 || useradd --system --gid vpn-node --no-create-home --shell /usr/sbin/nologin vpn-node
install -d -m 750 -o root -g vpn-node /etc/vpn-node /var/lib/vpn-node/textfile
for f in ca.crt cert.pem key.pem web.yml; do install -m 640 -o root -g vpn-node "$stage/$f" "/etc/vpn-node/$f"; done
install -m 644 "$stage/capacity.prom" /var/lib/vpn-node/textfile/capacity.prom
if ! test -x /usr/local/bin/vpn-node-exporter || ! /usr/local/bin/vpn-node-exporter --version 2>&1 | head -1 | grep -F "version $version " >/dev/null; then
  work=$(mktemp -d)
  trap 'rm -rf "$work"' EXIT
  archive="node_exporter-${version}.linux-amd64.tar.gz"
  curl --fail --location --retry 3 --max-time 180 "https://github.com/prometheus/node_exporter/releases/download/v${version}/${archive}" -o "$work/$archive"
  printf '%s  %s\n' "$checksum" "$work/$archive" | sha256sum --check --status
  tar xzf "$work/$archive" -C "$work"
  install -m 755 "$work/node_exporter-${version}.linux-amd64/node_exporter" /usr/local/bin/vpn-node-exporter
fi
cat > /etc/systemd/system/vpn-node-exporter.service <<EOF
[Unit]
Description=VPN Node Exporter (mutual TLS)
After=network-online.target
Wants=network-online.target
[Service]
User=vpn-node
Group=vpn-node
ExecStart=/usr/local/bin/vpn-node-exporter --web.listen-address=$listen_address --web.config.file=/etc/vpn-node/web.yml --collector.textfile.directory=/var/lib/vpn-node/textfile
Restart=always
RestartSec=3
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
MemoryMax=128M
CPUQuota=20%
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now vpn-node-exporter
systemctl restart vpn-node-exporter
systemctl is-active vpn-node-exporter
