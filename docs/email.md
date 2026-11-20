# Почтовые уведомления VPN

Alertmanager отправляет уведомления на два настроенных адреса. Реальные адреса, SMTP-логин и пароль хранятся в private `.local/smtp.json`. Итоговый YAML хранится в `.local/alertmanager.yml` и GitHub Secret `production/VPN_ALERTMANAGER_CONFIG`.

Используется существующий SMTP-аккаунт на mail-хосте из `~/.ssh/config`: TCP ${VPN_SMTP_PORT} с implicit TLS и обязательной проверкой сертификата. TCP ${VPN_SMTP_STARTTLS_PORT} на этом сервере не принимает соединения. Настройки Mailu, его учётные записи и `~/.ssh/config` автоматизация не меняет.

## Изменить отправителя или получателей

Редактируйте только private файл (пример с placeholders):

```json
{
  "host": "smtp.example.com",
  "port": "${VPN_SMTP_PORT}",
  "username": "alerts@example.com",
  "password": "SMTP_APPLICATION_PASSWORD",
  "to": ["recipient-one@example.com", "recipient-two@example.com"]
}
```

Поле `from` необязательно, по умолчанию равно `username`. Для STARTTLS поддержан порт ${VPN_SMTP_STARTTLS_PORT}. Вместо хранения логина/пароля в JSON можно передать `VPN_SMTP_USERNAME` и `VPN_SMTP_PASSWORD` в окружении процесса. Не сохраняйте их в публичном `.env.example` и не включайте shell trace.

```bash
# Только сформировать private YAML:
python3 scripts/configure_email.py

# Проверить SMTP-авторизацию с входного сервера, применить и обновить GitHub Secret:
python3 scripts/configure_email.py --apply --publish-secret
```

Скрипт проверяет TLS и авторизацию до замены рабочего YAML. Проверка авторизации сама не отправляет писем. Команда с `--apply` горячо перечитывает правила Prometheus и маршруты Alertmanager с автоматическим откатом при ошибке. Секреты передаются через stdin SSH и GitHub CLI.

`render.py` автоматически сохраняет private SMTP override при последующей генерации. CI получает тот же YAML через существующий Secret; workflow остаются ручными, `VPN_DEPLOY_ENABLED=false`, их запуск в эту настройку не входит.

## Группировка и проверка

`NodeUnavailable` остаётся виден в Alertmanager до восстановления. При новой недоступности узла приходит по одному письму каждому получателю, без напоминаний и письма о восстановлении. Короткоживущий `NodeUnavailableNotification` доставляется в первые 20 минут с начала сбоя и группируется по узлу и времени начала. После устойчивого восстановления следующий сбой получит собственное уведомление.

Пока недоступен узел, Alertmanager подавляет сообщения о его портах и ресурсах. Обычный пул и VPN Auto имеют независимые резервы, поэтому отказ всего пула отправляется отдельным уведомлением. Для остальных алертов действуют группировка по `alertname, host`, первая отправка через 30 секунд, повтор раз в 4 часа и уведомление о восстановлении.

Для проверки используется отдельный кратковременный `VpnEmailDeliveryTest`, помеченный как тест. Сбой серверов или VPN для проверки не имитируется. Подтверждение отправки: счётчики `alertmanager_notifications_total{integration="email"}` без ошибок и журналы SMTP с приёмом Gmail. Это подтверждает приём почтовым сервером получателя, а не расположение письма во «Входящих».

## Защита и откат

На входном сервере рабочий SMTP YAML имеет владельца `root:65534`, права `640`; до замены `amtool check-config` проверяет candidate. Если reload не удался, прежний YAML автоматически возвращается. Backup до первого включения почты: `/var/backups/vpn-infra/alertmanager-20261016T132406Z/alertmanager.yml`, права `600`.

Для ручного возврата на прежний web-only режим через SSH входного сервера:

```bash
sudo python3 /opt/vpn-infra/staging/entry/alertmanager/refresh_alertmanager.py \
  /var/backups/vpn-infra/alertmanager-20261016T132406Z/alertmanager.yml
```

После отката синхронизируйте `.local/alertmanager.yml` и GitHub Secret, иначе будущий deploy восстановит почту. При ротации пароль существующего SMTP-аккаунта меняет владелец mail-сервера; затем обновляются private настройки и Secret. Закрытый SSH-ключ ноутбука на VPN-сервер не копируется.
