#!/usr/bin/env bash
set -euo pipefail
stage=$1
install -d -m 750 /opt/vpn-balancer /etc/vpn-balancer
getent group vpn-balancer >/dev/null || groupadd --system vpn-balancer
id vpn-balancer >/dev/null 2>&1 || useradd --system --gid vpn-balancer --no-create-home --shell /usr/sbin/nologin vpn-balancer
# Keep a separate copy of the tested running version; x-ui updates do not replace it.
test -x /opt/vpn-balancer/xray || install -m 755 /usr/local/x-ui/bin/xray-linux-amd64 /opt/vpn-balancer/xray
for data in geoip.dat geosite.dat; do
  if [ -f "/usr/local/x-ui/bin/$data" ]; then install -m 644 "/usr/local/x-ui/bin/$data" "/opt/vpn-balancer/$data"; fi
done
export XRAY_LOCATION_ASSET=/opt/vpn-balancer
/opt/vpn-balancer/xray run -test -config "$stage/config.json"
chown root:vpn-balancer /etc/vpn-balancer /opt/vpn-balancer
install -m 640 -o root -g vpn-balancer "$stage/config.json" /etc/vpn-balancer/config.json
cat > /etc/systemd/system/vpn-balancer.service <<'EOF'
[Unit]
Description=Xray VPN egress pool with active health checks
After=network-online.target
Wants=network-online.target
[Service]
User=vpn-balancer
Group=vpn-balancer
WorkingDirectory=/opt/vpn-balancer
Environment=XRAY_LOCATION_ASSET=/opt/vpn-balancer
ExecStart=/opt/vpn-balancer/xray run -config /etc/vpn-balancer/config.json
Restart=always
RestartSec=2
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
MemoryMax=256M
LimitNOFILE=65536
UMask=0077
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now vpn-balancer
systemctl is-active vpn-balancer
