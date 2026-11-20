# Grafana по HTTPS

Адрес HTTPS: `${VPN_GRAFANA_URL}`. Корень `/` перенаправляет в `/grafana/`. Grafana принимает те же логин и пароль, которые сохранены в `.local/access.md`.

Отдельный контейнер `vpn-grafana-https` занимает только TCP `${VPN_MONITORING_HTTPS_PORT}`. Он передаёт запросы существующей Grafana на `${VPN_LOOPBACK_IP}:${VPN_GRAFANA_PORT}`. Порт `${VPN_MONITORING_HTTP_PORT}`, настройки самой Grafana, Prometheus, Alertmanager, подписки и VPN не меняются. На `${VPN_MONITORING_HTTPS_PORT}` доступны только маршруты Grafana. Для входа предпочтителен HTTPS.

Шаблон `monitoring/nginx-grafana-https.conf` переписывает канонические HTTP-ссылки, которые Grafana отдаёт в HTML, JSON и редиректах, на HTTPS. Статические файлы, API и WebSocket проходят по тому же пути. HTTPS-прокси добавляет флаг `Secure` к cookie; старый HTTP-фронт не меняется.

Установщик `scripts/install_grafana_https.py` на входном сервере принимает шаблон и публичный IPv4:

```bash
sudo python3 install_grafana_https.py install nginx-grafana-https.conf --address "${VPN_ENTRY_ADDRESS}"
```

Он отказывается занимать уже используемый порт или перезаписывать существующую установку. Сначала проверяет сертификат и конфигурацию nginx, затем проверяет TLS, перенаправление, страницу входа и API. Используется тот же закреплённый образ nginx, что у HTTP-мониторинга.

HTTPS читает сертификат из `/etc/vpn-failover-subscription/tls.pem`. Директория подключена к контейнеру только для чтения: закрытый ключ остаётся на сервере. Выпуск сертификата выполняет действующая система ACME x-ui, а таймер подписки обновляет локальную копию. Таймер `vpn-grafana-https-certificate.timer` раз в пять минут сравнивает предъявляемый сертификат с копией, проверяет доверие и IP, и перечитывает конфигурацию только при смене сертификата.

Для отключения только HTTPS:

```bash
sudo systemctl disable --now vpn-grafana-https-certificate.timer
sudo docker stop vpn-grafana-https
```

Старые HTTP-адреса сохранятся.
