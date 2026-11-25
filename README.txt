# UniChatServerd

**Автор оригинального сервера чата — Сергей Рихмайер (s.rihmayer@mail.ru).** Авторство исходного серверного проекта не принадлежит владельцу этого репозитория. Этот репозиторий содержит работу по адаптации, исправлению и развёртыванию совместимого сервера; эти изменения не являются заявлением об авторстве оригинального проекта.

TCP-ретранслятор для клиентов UniChat / Intranet Chat. Сервер принимает TCP-подключения, закрепляет первое полученное имя клиента за соединением и пересылает пакеты адресату или всем подключённым клиентам.

Сервер не хранит содержимое переписки и не доставляет сообщения отключённым пользователям. Для диагностики ведётся отдельный журнал метаданных сессий и маршрутизации в SQLite с автоматическим сроком хранения 20 дней. Обнаружение клиентов через UDP не реализовано; клиенты должны подключаться к адресу сервера самостоятельно.

## Требования

- Ubuntu Server 24.04 LTS (Minimal подходит).
- .NET SDK 10 для сборки.
- Для VM на Proxmox: начальная конфигурация 1 vCPU, 1 ГБ RAM, диск 8–16 ГБ, VirtIO.
- TCP-порт по умолчанию: 6666.

## Сборка на Ubuntu 24.04

Установка репозитория Microsoft и SDK:

```bash
sudo apt update
sudo apt install -y wget ca-certificates
wget https://packages.microsoft.com/config/ubuntu/24.04/packages-microsoft-prod.deb -O /tmp/packages-microsoft-prod.deb
sudo dpkg -i /tmp/packages-microsoft-prod.deb
rm /tmp/packages-microsoft-prod.deb
sudo apt update
sudo apt install -y dotnet-sdk-10.0
```

Сборка автономного single-file приложения для x86-64:

```bash
git clone https://github.com/darkovichk-create/unichat-srv.git
cd unichat-srv
dotnet publish UniChatServerd.csproj -c Release -r linux-x64 --self-contained true \
  -p:PublishSingleFile=true -o ./publish
```

Для ARM64 VM замени RID на `linux-arm64`. Trimming намеренно не включён: сначала лучше получить предсказуемую сборку, а оптимизацию размера делать отдельно.

## Установка как systemd-службы

Создать системного пользователя и каталог приложения:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin unichatd
sudo install -d -o root -g root -m 0755 /opt/unichatd
sudo cp -a ./publish/. /opt/unichatd/
sudo chown -R root:root /opt/unichatd
sudo chmod 0755 /opt/unichatd/UniChatServerd
```

Создать файл службы:

```bash
sudo nano /etc/systemd/system/unichatd.service
```

Содержимое (замени IP на адрес VM, доступный клиентам):

```ini
[Unit]
Description=UniChatServerd (.NET 10 TCP relay)
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=notify
User=unichatd
Group=unichatd
WorkingDirectory=/opt/unichatd
StateDirectory=unichatd
StateDirectoryMode=0750
ExecStart=/opt/unichatd/UniChatServerd --ip 192.168.1.50 --port 6666 --log-level Information
Restart=on-failure
RestartSec=5

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictAddressFamilies=AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
```

Запуск и проверка:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now unichatd.service
sudo systemctl status unichatd.service
journalctl -u unichatd.service -f
```

Логи Linux-службы выводятся в journald. Приложению не требуется право записи в каталог установки.

### Журнал событий SQLite

При первом запуске сервер создаёт базу метаданных `/var/lib/unichatd/audit.db` (каталог `StateDirectory=unichatd` создаёт systemd и назначает владельцем пользователя службы). На Windows-службе используется `%ProgramData%\\UniChatServerd\\audit.db`. Путь можно переопределить параметром `--audit-db /путь/к/audit.db`.

В базе сохраняются:
- время события в UTC с точностью до миллисекунд;
- открытие/закрытие TCP-сессии, ClientId, IP клиента и длительность сессии;
- ошибки framing/протокола, сетевые ошибки, дубликаты ClientId и переполнение исходящей очереди;
- факт маршрутизации, адресат, размер пакета и результат постановки в исходящую очередь;
- запуск/остановка сервера и предупреждения завершения.

**Тело сообщений и вложений в SQLite не записывается.** Для личных сообщений фиксируются только метаданные маршрутизации. Статус `queued_to_socket_queue` означает, что пакет поставлен в очередь отправки, а не подтверждение фактического получения клиентом.

Используется SQLite в WAL-режиме с асинхронной ограниченной очередью и пакетной записью. Старые события удаляются при старте и далее не реже одного раза в час; срок хранения — 20 дней. База предназначена для оперативной диагностики, а не для долговременного архива или аналитического хранилища.

## Сетевой доступ

Разреши TCP/6666 только из нужной локальной сети. Например, если клиенты находятся в сети 192.168.1.0/24:

```bash
sudo ufw allow from 192.168.1.0/24 to any port 6666 proto tcp
```

Проверь также firewall Proxmox и сетевые ACL/VLAN, если они используются. Не публикуй порт в Интернет без VPN или защищённого туннеля: текущий протокол не шифрует трафик и не обеспечивает полноценную аутентификацию пользователей.

## Протокол и ограничения

- TCP — потоковый транспорт. Заголовок размера имеет переменную длину и завершается нулевым байтом; сервер читает его до разделителя, затем дочитывает ровно тело пакета.
- Содержимое тела не преобразуется: сервер пересылает байты без изменений. Это позволяет ретранслировать текстовые и бинарные данные, если клиент передаёт их в совместимых пакетах.
- Максимальный размер тела одного пакета сейчас ограничен 128 КиБ. Если передача файла использует несколько небольших фрагментов, они могут проходить через сервер как обычные пакеты. Если клиент отправляет файл одним большим пакетом, потребуется согласованно изменить лимит и формат/ограничения очередей.
- Сервер не реализует отдельный протокол передачи файлов, хранение файлов или возобновление прерванной передачи. Для этого необходима поддержка на стороне клиента и точное описание его формата файловых сообщений.
- Первое сообщение TCP-соединения закрепляет ID клиента. Последующие пакеты с другим ID отклоняются. Это проверка целостности сессии, а не криптографическая аутентификация.

## Проверка

После запуска подключи два клиента к одному IP и TCP-порту. Проверь:
1. появление обоих подключений в журнале;
2. отправку широковещательного сообщения;
3. отправку личного сообщения;
4. отключение одного клиента и повторное подключение с тем же ID;
5. пакеты с телом разной длины, в том числе короче 16 байт после заголовка.

Перед эксплуатацией с реальными файлами отдельно проверь файловый сценарий клиента и максимальный размер его фрагментов.
