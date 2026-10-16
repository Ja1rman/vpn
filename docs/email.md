# Почтовые уведомления VPN

Alertmanager отправляет все существующие алерты и уведомления о восстановлении на два настроенных адреса. Реальные адреса, SMTP-логин и пароль хранятся в private `.local/smtp.json`; итоговый YAML — `.local/alertmanager.yml` и GitHub Secret `production/VPN_ALERTMANAGER_CONFIG`. В публичный Git эти значения не входят.

Используется существующий SMTP-аккаунт на mail-хосте из `~/.ssh/config`: TCP465 с implicit TLS и обязательной проверкой сертификата. TCP587 на этом сервере не принимает соединения. Настройки Mailu, его учётные записи и `~/.ssh/config` автоматизация не меняет.

## Изменить отправителя или получателей

Редактируйте только private файл (пример с placeholders):

```json
{
  "host": "smtp.example.com",
  "port": 465,
  "username": "alerts@example.com",
  "password": "SMTP_APPLICATION_PASSWORD",
  "to": ["recipient-one@example.com", "recipient-two@example.com"]
}
```

Поле `from` необязательно, по умолчанию равно `username`. Для STARTTLS поддержан порт587. Вместо хранения логина/пароля в JSON можно передать `VPN_SMTP_USERNAME` и `VPN_SMTP_PASSWORD` в окружении процесса. Не сохраняйте их в публичном `.env.example` и не включайте shell trace.

```bash
# Только сформировать private YAML:
python3 scripts/configure_email.py

# Проверить SMTP-авторизацию с входного сервера, применить и обновить GitHub Secret:
python3 scripts/configure_email.py --apply --publish-secret
```

Скрипт проверяет TLS и авторизацию до замены рабочего YAML. Проверка авторизации сама не отправляет писем. Команда с `--apply` перечитывает только Alertmanager через `POST /-/reload`; VPN, x-ui, контейнеры мониторинга и mail-сервер не перезапускаются. Секреты передаются по SSH stdin и stdin GitHub CLI, не аргументами команд.

`render.py` автоматически сохраняет private SMTP override при последующей генерации. CI получает тот же YAML через существующий Secret; workflow остаются ручными, `VPN_DEPLOY_ENABLED=false`, их запуск в эту настройку не входит.

## Группировка и проверка

Группировка по `alertname, host`, первая отправка через 30 секунд, обновление группы раз в 5 минут, повтор активной аварии раз в 4 часа. У каждого получателя отдельный email config; включён `send_resolved`. Условия срабатывания Prometheus и подавление вторичных warning при `NodeUnavailable` сохранены. Тема письма содержит `[VPN]`, статус, имя алерта и сервер; тело — описание и labels.

Для проверки используется отдельный кратковременный `VpnEmailDeliveryTest`, помеченный как тест. Сбой серверов или VPN для проверки не имитируется. Подтверждение отправки: счётчики `alertmanager_notifications_total{integration="email"}` без ошибок и журналы SMTP с приёмом Gmail. Это подтверждает приём почтовым сервером получателя, а не расположение письма во «Входящих».

## Защита и откат

На входном сервере рабочий SMTP YAML имеет владельца `root:65534`, права `640`; до замены `amtool check-config` проверяет candidate. Если reload не удался, прежний YAML автоматически возвращается. Backup до первого включения почты: `/var/backups/vpn-infra/alertmanager-20261016T132406Z/alertmanager.yml`, права `600`.

Для ручного возврата на прежний web-only режим через SSH входного сервера:

```bash
sudo python3 /opt/vpn-infra/staging/entry/alertmanager/refresh_alertmanager.py \
  /var/backups/vpn-infra/alertmanager-20261016T132406Z/alertmanager.yml
```

После отката синхронизируйте `.local/alertmanager.yml` и GitHub Secret, иначе будущий deploy восстановит почту. При ротации пароль существующего SMTP-аккаунта меняет владелец mail-сервера; затем обновляются private настройки и Secret. Закрытый SSH-ключ ноутбука на VPN-сервер не копируется.
