# Telegram: WEB и резервные входы

Для MTProto и SOCKS5 добавьте в Telegram основной и резервный профили из закрытых access-файлов, затем включите **Автоматически переключать прокси / Auto-Switch Proxies**. При отказе текущего подключения Telegram выбирает следующий сохранённый прокси. Реквизиты разных входов могут отличаться. Это штатная возможность [Telegram](https://core.telegram.org/proxy), которую нужно включить на каждом устройстве.

Основной вход использует приоритетный VPN Auto; резервный вход на NL работает независимо от входного сервера и выходит с NL. Старые адреса и ключи сохраняются. Уже установленная TCP-сессия при физическом отказе сервера потребует переподключения: переключение не переносит существующий сокет между хостами.

Состояние проверки: MTProto EE и DD прошли настоящий Telegram RPC через оба публичных входа. SOCKS5 через оба входа проходит авторизацию, CONNECT и HTTPS с проверкой сертификата; его Telegram RPC успешно выполняется на каждом сервере с теми же реквизитами. Публичный Telegram-тест SOCKS с Mac пока завершается тайм-аутом. Активный Network Extension не позволяет считать эти проверки тестом без VPN; доступность из проблемной Wi-Fi-сети не подтверждена.

## Публичный вход и развёртывание

Классификатор `vpn-tcp-demux` позволяет MTProto EE/DD и SOCKS5 использовать тот же стандартный TLS-порт, что уже занят существующим обработчиком. Обычный TLS передаётся прежнему listener; входы, ключи и session map Xray не переносятся. Текущие соединения сохраняют прежний путь. Правило NAT ограничено выбранным интерфейсом, фактическим локальным адресом, портом и только новым initial SYN. Цепочки OUTPUT/INPUT и conntrack не очищаются.

Если публичный адрес реализован облачным NAT, `VPN_ENTRY_INGRESS_IP` и `VPN_NL_INGRESS_IP` задают адреса интерфейсов внутри VPS; клиентские адреса остаются `VPN_ENTRY_ADDRESS` и `VPN_NL_ADDRESS`. Также задайте соответствующие `VPN_*_INGRESS_INTERFACE` и свободные `VPN_*_TELEGRAM_MUX_PORT`. Backends принимают только loopback; прямые подключения к техническому listener отвергаются проверкой исходного назначения.

```bash
# Сначала отдельные независимые backends NL:
python3 scripts/vpnctl.py deploy-telegram-reserve
# Классификатор устанавливается без перенаправления публичного трафика:
python3 scripts/deploy_tcp_demux.py install --host breeze-reef
# Включение с watchdog, реальным native-клиентом и автоматическим commit/rollback:
python3 scripts/deploy_tcp_demux.py activate --host breeze-reef
# Аналогично для основного входа после подготовки его существующих backends:
python3 scripts/deploy_tcp_demux.py install --host entry
python3 scripts/deploy_tcp_demux.py activate --host entry
```

Подтверждение требует настоящего DH/RPC для всех трёх протоколов и исправного исходного TLS. Отчёт связан с транзакцией, сохраняется в `.local/tcp-demux/`; при неуспехе или отсутствии подтверждения за 180 секунд снимается только принадлежащее проекту перенаправление. Уже перенаправленные соединения обслуживаются до завершения. При остановке classifier новые подключения возвращаются к исходному listener. Перезагрузка восстанавливает только подтверждённую конфигурацию.

Для текущей установки явно выбран режим `--socks-proof https`: MTProto всё равно требует публичного Telegram RPC, а SOCKS — публичного HTTPS и свежего Telegram RPC на собственном сервере. On-host probe читает уже установленные реквизиты только на этом хосте, сравнивает их digest с локальным профилем и не передаёт ключи между серверами. Отчёт сохраняет `native_socks: false`; этот режим не означает исправление внешнего Telegram через SOCKS. Порт проверочного HTTPS-назначения задаётся отдельно в `VPN_TELEGRAM_VERIFY_HTTPS_PORT`.

```bash
python3 scripts/deploy_tcp_demux.py activate --host breeze-reef --socks-proof https
python3 scripts/deploy_tcp_demux.py activate --host entry --socks-proof https
```

Ручной откат публичного перенаправления, без остановки обслуживаемых соединений:

```bash
python3 scripts/deploy_tcp_demux.py rollback --host breeze-reef
```

Реквизиты: основной вход в `.local/telegram-proxies/entry/`, резервный в `.local/telegram-reserve/nl/`, общая инструкция со ссылками в `.local/telegram-proxies/access.md`. Стабильные ключи резерва можно восстановить через защищённый `VPN_TELEGRAM_RESERVE_CREDENTIALS_JSON`; несовпадающее значение не ротирует существующие ключи автоматически.

## WEB

Используется официальный [Telegram WEB relay](https://github.com/telegramdesktop/tproxy-server) с HTTPS/WebView-транспортом и локальным MTProto DD backend. Это отдельный тип Telegram WEB, а не обычный HTTP CONNECT. Нужен клиент, поддерживающий этот экспериментальный тип и ссылку `tg://webproxy`.

В закрытом окружении задайте `VPN_WEB_PROXY_ADDRESS` как DNS-имя, направленное на `VPN_ENTRY_ADDRESS`. Нужен стандартный HTTPS-вход, заданный через `VPN_MONITORING_HTTPS_PORT`; relay/admin/ACME используют отдельные свободные loopback-порты `VPN_WEB_PROXY_PORT`, `VPN_WEB_PROXY_ADMIN_PORT`, `VPN_WEB_ACME_PORT`.

С ноутбука:

```bash
python3 scripts/deploy_web_proxy.py --prepare-only
python3 scripts/vpnctl.py deploy-web-proxy
# Только после появления корректной A-записи и отсутствия чужой AAAA-записи:
python3 scripts/deploy_web_tls.py
python3 scripts/verify_web_proxy.py \
  --settings .local/web-proxy/proof-settings.json \
  --native-probe .local/telegram-probe/telegram-probe --dc 2
```

Готовая ссылка сохраняется в `.local/web-proxy/access.md`. WEB опубликован на настроенном DNS-имени; публичный HTTPS с проверкой сертификата и полный Telegram DH/RPC успешно проверены для двух центров данных. Корень домена в браузере намеренно отвечает 404: подключение выполняется через ссылку `tg://webproxy` в клиенте с поддержкой WEB. Проверка без VPN в проблемной Wi-Fi-сети отдельно не подтверждена. Секрет, путь и signing key сохраняются в `.local/web-proxy/credentials.json`; при восстановлении передайте неизменённый файл или защищённый `VPN_WEB_PROXY_CREDENTIALS_JSON`.

Для смены ещё не опубликованного имени relay обновите только `VPN_WEB_PROXY_ADDRESS` в закрытом окружении и выполните явную миграцию:

```bash
python3 scripts/deploy_web_proxy.py --previous-hostname "${VPN_WEB_PREVIOUS_ADDRESS}"
python3 scripts/deploy_web_tls.py
```

`VPN_WEB_PREVIOUS_ADDRESS` здесь — прежнее DNS-имя, которое вы явно передаёте команде. Миграция проверяет совпадение всей установки, меняет только hostname с резервной копией и откатом, сохраняет ключи и путь; перезапускается только WEB-relay. Уже опубликованные nginx/ACME server-блоки автоматическая hostname-миграция не заменяет: сначала требуется отдельная согласованная миграция TLS. Обычный повторный deploy по-прежнему отказывается перезаписывать отличающуюся установку.

`install_web_tls.py` добавляет отдельные hostname server-блоки в существующий nginx. ACME слушает только loopback, challenge передаётся ему через HTTP; Grafana сохраняет IP-сертификат и маршруты. Перед записью проверяются candidate и исходные байты; применяется только graceful HUP. Сертификат WEB, реально предъявляемый nginx, проверяется по SHA256 и доверенному DNS-имени. Отдельный таймер `vpn-telegram-web-certificate.timer` выполняет продление. Рабочие VPN-службы не перезапускаются.

WEB на одном DNS-имени переживает отказ выходного сервера через VPN Auto, но пока зависит от основного входа. В [эталонном Android-клиенте WEB исключён из автоматической ротации](https://github.com/telegramdesktop/tproxy-server/blob/master/ANDROID.md). Для автоматического резервирования самого WEB-входа требуется отдельная настройка DNS health failover или внешний отказоустойчивый вход; добавление второй ссылки само по себе этого не обеспечивает.

## Как трактовать проверки

TCP open и успешная авторизация SOCKS не доказывают работу Telegram. Проверки проекта выполняют настоящий DH/auth-key обмен и Telegram RPC без входа в аккаунт. WEB проверяется также через строгий TLS и штатный carrier-протокол. Выбор физического интерфейса Mac не исключает перехват прозрачным Network Extension; результаты такого теста не следует подписывать «без VPN».
