# GitHub: публикация и развёртывание

Репозиторий: [Ja1rman/vpn](https://github.com/Ja1rman/vpn), SSH remote `git@github.com:Ja1rman/vpn.git`. Он публичный. В Git находятся код, inventory, шаблоны и документация; `.local/`, реальные env-файлы, ключи, сертификаты и базы исключены.

По просьбе владельца оба workflow имеют **только `workflow_dispatch`**. Push, PR и расписание их не запускают. Развёртывание дополнительно выключено переменной репозитория `VPN_DEPLOY_ENABLED=false`. В рамках публикации CI не запускался и не тестировался; подготовленный путь развёртывания требует первой проверки после восстановления лимитов Actions.

## Переменные и секреты

В **Settings → Secrets and variables → Actions → Variables**:

| Repository variable | Значение |
|---|---|
| `VPN_DEPLOY_ENABLED` | `false` до разрешения запусков; `true` для ручного развёртывания |
| `VPN_MONITORING_USERNAME` | `admin` |

В **Settings → Environments → production → Environment secrets**:

| Secret | Содержимое |
|---|---|
| `VPN_SSH_PASSWORDS_JSON` | JSON: имя хоста из inventory → SSH-пароль |
| `VPN_SSH_KNOWN_HOSTS` | Подтверждённые строки `known_hosts`; проверка ключей обязательна |
| `VPN_OUTBOUNDS_JSON` | JSON: путь outbound из inventory → полный клиентский outbound Xray |
| `VPN_MONITORING_PASSWORD` | Действующий пароль Grafana/HTTP Basic Auth, не короче 24 символов |
| `VPN_MONITORING_TLS_JSON` | CA **сертификат**, клиентская и серверные пары сертификат/ключ для Node Exporter |
| `VPN_ALERTMANAGER_CONFIG` | Необязательно: полный private YAML Alertmanager с SMTP. При отсутствии используется tracked `web-only` |

Workflow передаёт Secrets в окружение шага deploy; `ci_environment.py` создаёт из них файлы с правами `600` в закрытой `.local/`. JSON-секреты и вложенные строковые значения добавляются в маскирование логов. Секреты не передаются аргументами CLI, не публикуются в artifacts/cache; `.local/` удаляется в завершающем шаге даже при ошибке.

Формат двух основных JSON-секретов (только placeholders):

```json
{
  "VPN_SSH_PASSWORDS_JSON": {
    "entry": "SSH_PASSWORD_ENTRY",
    "breeze-reef": "SSH_PASSWORD_EXIT"
  },
  "VPN_OUTBOUNDS_JSON": {
    ".local/outbounds/exit-example.json": {
      "protocol": "vless",
      "settings": {
        "address": "203.0.113.10",
        "port": 443,
        "id": "UUID_FROM_X_UI",
        "encryption": "none"
      }
    }
  }
}
```

В каждом Secret сохраняется значение соответствующего внутреннего объекта, без внешнего имени. Полные transport/REALITY/TLS-поля outbound должны соответствовать существующему выходу; пример выше показывает только схему хранения.

Формат `VPN_MONITORING_TLS_JSON`:

```json
{
  "ca_cert": "PEM_CA_CERTIFICATE",
  "client": {"cert": "PEM_CLIENT_CERTIFICATE", "key": "PEM_CLIENT_KEY"},
  "nodes": {
    "entry": {"cert": "PEM_SERVER_CERTIFICATE", "key": "PEM_SERVER_KEY"},
    "breeze-reef": {"cert": "PEM_SERVER_CERTIFICATE", "key": "PEM_SERVER_KEY"}
  }
}
```

Закрытый ключ CA `.local/pki/ca.key`, пользовательская база x-ui, ключи WireGuard-входов, резервные архивы и binary runtime в GitHub Secrets не загружаются. CI использует уже выданные leaf-сертификаты; новые сертификаты выпускайте локально прежней CA. Для большого числа узлов учитывайте лимит 48 КиБ на один Secret и разделите TLS/outbounds на несколько Secrets при необходимости.

## Загрузка и обновление Secrets с ноутбука

Для GitHub CLI нужна действующая авторизация с правом управления Secrets и Environment в этом репозитории:

```bash
gh auth login
python3 scripts/sync_github_secrets.py --repo Ja1rman/vpn
```

Скрипт читает текущие файлы `.local/ssh`, `.local/outbounds`, `.local/access.json` и leaf-пары `.local/pki`; общий plaintext-архив не создаёт. GitHub CLI шифрует значения перед отправкой в API. Он создаёт Environment `production` с доступом к развёртыванию только из ветки `main`, обновляет пять обязательных Secrets и логин, затем всегда оставляет `VPN_DEPLOY_ENABLED=false`. После синхронизации для будущего deploy снова включите переменную явно.

Если существует `.local/alertmanager.yml`, его содержимое тоже сохраняется в `VPN_ALERTMANAGER_CONFIG`. Если файла нет, существующий optional Secret не удаляется. Для отключения ранее настроенной почты удалите optional Secret отдельно или загрузите согласованный web-only YAML. Сейчас SMTP не настроен.

## Ручной запуск после восстановления лимитов

1. Откройте **Actions → Validate infrastructure configuration → Run workflow**, ветка `main`. Этот workflow не получает production Secrets и не подключается к VPN-серверам.
2. Установите repository variable `VPN_DEPLOY_ENABLED=true`.
3. Откройте **Actions → Deploy VPN infrastructure → Run workflow**, ветка `main`, и выберите компонент.

| Component | Действие |
|---|---|
| `dashboards` (по умолчанию) | Дашборды и файлы доступа мониторинга; nginx перечитывает конфигурацию |
| `pool` | Горячее обновление outbounds/routing отдельного балансировщика |
| `monitoring` | Compose: Prometheus, Alertmanager, Blackbox, Grafana, nginx |
| `node-exporters` | Обновление Node Exporter на входном и выходных серверах |
| `all` | Node Exporter → мониторинг → горячее обновление пула |

До изменения каждого затрагиваемого сервера создаётся private backup в `/var/backups/vpn-infra/ci/<UTC>-<run-id>-<attempt>/configuration.tar.gz`, права каталога `700`, архива `600`. Его можно забрать по SSH; в публичные Actions artifacts архив не попадает. Архивы автоматически не удаляются.

Деплои выполняются последовательно (`concurrency`, без отмены работающего deploy новым запуском). Основной x-ui и его входы этот workflow не меняет и не перезапускает. Замена ключей активного outbound под прежним tag отклоняется: добавьте выход с новым именем, проверьте его, затем уберите старый. Мониторинг и Node Exporter могут перезапускаться при соответствующем обновлении. Bootstrap нового VPS и первичная миграция клиентских маршрутов остаются отдельными локальными командами.

## Добавление хоста

Подготовьте VPS через `add_host.py`, сохраните проверенный SSH host key и пароль в `.local/ssh/ИМЯ.password`, добавьте outbound/inventory, локально выпустите сертификат Node Exporter прежней CA. Выполните `sync_github_secrets.py`, затем запушьте публичные изменения inventory. После включения переменной можно вручную развернуть `all`. Сам push по-прежнему ничего не запускает.

## Источники

- [GitHub: ручные триггеры workflow](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow).
- [GitHub: Secrets в окружении Actions](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/use-secrets).
