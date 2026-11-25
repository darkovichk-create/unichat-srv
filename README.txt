#включить логин от рута по ssh (чтобы закинуть файлы)
nano /etc/ssh/sshd_config
PermitRootLogin yes
systemctl restart ssh


#компиляция
sudo apt update
apt install -y dotnet-sdk-10.0
cd UniChatServerd
dotnet publish -c Release -r linux-x64 --self-contained true -p:PublishSingleFile=true -p:PublishTrimmed=true -o ./publish


#создать отдельного юзера
useradd --system --no-create-home --shell /bin/false unichatd
#каталог
mkdir -p /opt/unichatd
#владелец
chown -R unichatd:unichatd /opt/unichatd
#копирование файлов приложения в /opt
cp -r ./publish/* /opt/unichatd/


#настройка systemd юнита, НУЖНО УСТАНОВИТЬ IP СЕРВЕРА В КОНФИГУРАЦИИ
nano /etc/systemd/system/unichatd.service

### содержимое файла ->
[Unit]
Description=UniChatServerd (.NET 10 TCP Server)
After=network.target

#protection against an infinite loop of crashes
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
#launching a dedicated user
User=unichatd
Group=unichatd

WorkingDirectory=/opt/unichatd
ExecStart=/opt/unichatd/UniChatServerd --ip 192.168.XXX.XXX --log-level Warning

ProtectSystem=strict
ReadWritePaths=/opt/unichatd

#restart policy
Restart=on-failure
#delay between restart attempts (in seconds)
RestartSec=10

### <-


systemctl daemon-reload
systemctl enable unichatd.service
systemctl start unichatd.service
systemctl status unichatd.service


#посмотреть логи
journalctl -u unichatd.service
в реальном времени
journalctl -u unichatd.service -f