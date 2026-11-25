// Original UniChat server author: Sergey Rihmayer (s.rihmayer@mail.ru)

using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Serilog;

namespace UniChatServerd
{

    public class TcpServerListener(IConfiguration configuration) : BackgroundService
    {
        private readonly IConfiguration configuration = configuration;
        private readonly IPAddress _ipAddress = IPAddress.Parse(configuration["ip"] ?? "127.0.0.1");
        private readonly int _port = int.Parse(configuration["port"] ?? "6666");
        private readonly ConnectionManager _connectionManager = new();
        private TcpListener? _server;


        /// <summary>
        /// Запускает TCP-сервер и начинает асинхронный прием подключений.
        /// </summary>
        protected override async Task ExecuteAsync(CancellationToken cancellationToken)
        {
            try
            {
                _server = new TcpListener(_ipAddress, _port);
                _server.Start();
                Log.Information("[СЕРВЕР] Запущен на {ServerIp}:{ServerPort}", _ipAddress, _port);

                // _ = LogBufferStatsAsync(cancellationToken); // debug

                // Регистрация Stop() на случай, если по какой-то причине
                // AcceptTcpClientAsync не отреагирует на отмену токена.
                // В современном .NET должно хватать одной отмены, но страховка дешёвая.
                using (cancellationToken.Register(() => _server.Stop()))
                {
                    while (!cancellationToken.IsCancellationRequested)
                    {
                        // Ждем подключения клиента без блокировки основного потока
                        TcpClient client = await _server.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(false);

                        try
                        {
                            // Настраиваем Keep-Alive для защиты от обрыва «молчаливых» сессий
                            ConfigureSocket(client.Client);
                            Log.Debug("[СЕРВЕР] Подключился новый клиент: {ClientIp}", client.Client.RemoteEndPoint);

                            var connection = new ClientConnection(client, _connectionManager, cancellationToken);

                            // Мгновенно отправляем клиента на обработку в фоновую задачу.
                            // Использование discard (_) сообщает компилятору, что мы не ждем (await) 
                            // завершения работы с этим клиентом прямо здесь, а сразу готовы принимать следующего.
                            // Запускаем без await, но с защитой от потери исключений
                            _ = HandleClientSafeAsync(connection);
                        }
                        catch (Exception ex)
                        {
                            Log.Warning(ex, "[СЕРВЕР] Не удалось принять клиента {ClientIp}", client.Client?.RemoteEndPoint);
                            client.Dispose();
                        }

                    }
                }
            }
            catch (OperationCanceledException)
            {
                Log.Information("[СЕРВЕР] Вызвана остановка через CancellationToken.");
            }
            // На всякий случай ловим закрытие сокета, если listener.Stop() вызвался раньше токена
            catch (Exception ex) when 
                ((ex is ObjectDisposedException || ex is SocketException) 
                            && cancellationToken.IsCancellationRequested)
            {
                Log.Information("[СЕРВЕР] Сокет закрыт в процессе остановки службы.");
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[СЕРВЕР] КРИТИЧЕСКАЯ ОШИБКА");
            }
            finally
            {
                _server?.Stop();
                Log.Information("[СЕРВЕР] ОСТАНОВЛЕН. Очистка ресурсов завершена.");
            }
        }


        // Отдельный приватный метод для безопасности
        private async Task HandleClientSafeAsync(ClientConnection connection)
        {
            try 
            { 
                await connection.HandleClientAsync(); 
            }
            catch (Exception ex) //when (ex is not OperationCanceledException)
            {
                Log.Debug(ex, "[СЕРВЕР] ОШИБКА СЕССИИ.");
            }
        }

        /// <summary>
        /// Конфигурация низкоуровневых настроек сокета.
        /// </summary>
        private void ConfigureSocket(Socket socket)
        {
            // Включаем встроенный механизм Keep-Alive на уровне ОС
            socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);

            // Время простоя до первой пробы: 30 секунд
            socket.SetSocketOption(
                SocketOptionLevel.Tcp,
                SocketOptionName.TcpKeepAliveTime,
                30);

            // Интервал между повторными пробами: 10 секунд
            socket.SetSocketOption(
                SocketOptionLevel.Tcp,
                SocketOptionName.TcpKeepAliveInterval,
                10);

            // Опционально: Отключаем алгоритм Нагла для мгновенной отправки ответов (снижает задержки/latency)
            socket.NoDelay = true;
        }

        //private async Task LogBufferStatsAsync(CancellationToken ct) // debug
        //{
        //    while (!ct.IsCancellationRequested)
        //    {
        //        try
        //        {
        //            await Task.Delay(TimeSpan.FromSeconds(10), ct);

        //            Log.Warning(
        //                "[BUFFER] Created={Created}, Disposed={Disposed}, Alive={Alive}",
        //                RefCountedBuffer.Created,
        //                RefCountedBuffer.Disposed,
        //                RefCountedBuffer.Alive);
        //        }
        //        catch (OperationCanceledException)
        //        {
        //            break;
        //        }
        //        catch (Exception ex)
        //        {
        //            Log.Error(ex, "[BUFFER] Ошибка в статистике");
        //        }
        //    }
        //}


    }


}
