# Как добавить VPN-сервер с ноутбука

**VPN Auto** использует первый доступный зарубежный выход из очереди `ihor → breeze-reef → srv-41969`. Добавляйте новый выход в конец, чтобы оставить прежний основной IP. Прямой TCP-маршрут к `.ru`, `.рф` и `.ру` сохраняется. На телефоне адрес входа и профили менять не нужно.

Команды выполняйте на ноутбуке из папки проекта (`cd ~/Documents/ChatGPT/vpn`). Нужны Python 3.10+, OpenSSH и уже настроенный SSH-доступ к входному серверу. Для примеров экспортируйте адрес нового выхода в `VPN_NEW_EXIT_ADDRESS` и выбранный TLS-порт в `VPN_EXIT_TLS_PORT`. [Как загружаются параметры окружения](../README.md#сетевые-параметры-из-окружения).

## Выход уже настроен в x-ui

В **x-ui входного сервера → Xray Configs → Outbounds** возьмите тег работающего исходящего VLESS с TLS или REALITY и его публичный IP. Добавьте его в конец массива `failover.egresses` в [inventory/hosts.json](../inventory/hosts.json):

```json
{"name": "exit-4", "address": "${VPN_NEW_EXIT_ADDRESS}", "source": "main", "tag": "exit-4-vless"}
```

Подставьте свои значения. Имя и IP должны отличаться от остальных выходов. Для выхода из старого пула укажите `"source": "legacy"` и его тег. Оставьте прежние строки в том же порядке: эта команда добавляет новый резерв последним. Примените на ноутбуке:

```bash
python3 scripts/vpnctl.py update-failover-pool
```

## Чистый VPS

Нужны Linux x86_64 с systemd и Python 3, публичный IPv4, root или `sudo` без пароля и свободный TCP-порт `${VPN_EXIT_TLS_PORT}`, открытый со входного сервера. С ноутбука выполните `ssh -o UserKnownHostsFile="$PWD/.local/ssh/known_hosts" "root@${VPN_NEW_EXIT_ADDRESS}"`. Подтвердите ключ, только если отпечаток совпал с консолью провайдера, и выйдите из SSH. При входе по паролю нужен `sshpass`: пароль сохраните в `.local/ssh/exit-4.password` и выполните `chmod 600 .local/ssh/exit-4.password`.

Подставьте своё имя, IP и SSH-пользователя:

```bash
python3 scripts/add_host.py --pool auto --name exit-4 --address "${VPN_NEW_EXIT_ADDRESS}" \
  --user root --provision --port "${VPN_EXIT_TLS_PORT}"
```

Скрипт поднимет VLESS/REALITY, проверит TCP и UDP и добавит резерв в **VPN Auto** без перезапуска рабочих VPN-служб. Другой свободный порт можно указать через `--port`. Если у вас уже есть JSON одного исходящего VLESS, замените `--provision --port "${VPN_EXIT_TLS_PORT}"` на `--outbound /путь/к/файлу.json`. Реквизиты хранятся в закрытой `.local/`. Старый пул меняется отдельно: [инструкция в README](../README.md#добавить-ещё-один-хост).

## Что импортировать на телефоне

- Старую подписку `https://${VPN_ENTRY_ADDRESS}:${VPN_SUBSCRIPTION_PORT}/sub/<SubID>` оставьте в приложении.
- Вторую добавьте отдельно: `https://${VPN_ENTRY_ADDRESS}:${VPN_AUTO_SUBSCRIPTION_PORT}/sub/<SubID>`. Из старой ссылки достаточно заменить порт `${VPN_SUBSCRIPTION_PORT}` на `${VPN_AUTO_SUBSCRIPTION_PORT}`. В NekoBox или Hiddify выберите единственный профиль **VPN Auto**. Путь `/failover/` на `${VPN_AUTO_SUBSCRIPTION_PORT}` тоже работает.

Обе подписки зависят от общего входного сервера `${VPN_ENTRY_ADDRESS}`. Резервирование защищает от отказа выхода. [Как устроены две подписки](two-subscriptions.md).
