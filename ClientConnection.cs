// Original UniChat server author: Sergey Rihmayer (s.rihmayer@mail.ru)

using Serilog;
using System;
using System.Buffers;
using System.Buffers.Text;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace UniChatServerd
{
    internal class ClientConnection
    {
        private readonly TcpClient _client;
        private readonly NetworkStream _stream;
        private readonly ConnectionManager _manager;
        private readonly CancellationToken _serverToken;
        private readonly CancellationTokenSource _sessionCts;
        private const int HeaderBufferSize = 16;
        private const int MaxPacketSize = 128 * 1024; // Защита от DoS: максимум на пакет
        private static readonly Encoding AnsiEncoding = Encoding.GetEncoding(1251);

        public string? ClientId { get; private set; }

        private static ReadOnlySpan<byte> ForwardMarker => "FORWARD"u8;

        private readonly Channel<RefCountedBuffer> _outgoing;
        private readonly Task _writerTask;
        private byte _closed;

        public ClientConnection(TcpClient client, ConnectionManager manager, CancellationToken serverToken)
        {
            _client = client;
            _manager = manager;
            _serverToken = serverToken;
            _sessionCts = CancellationTokenSource.CreateLinkedTokenSource(serverToken);
            _stream = client.GetStream();

            _outgoing = Channel.CreateBounded<RefCountedBuffer>(
                new BoundedChannelOptions(capacity: 256)
                {
                    SingleReader = true,        // один Writer-цикл на клиента
                    SingleWriter = false,       // писать могут несколько ридеров отправителей
                    FullMode = BoundedChannelFullMode.Wait,
                    AllowSynchronousContinuations = false
                });

            _writerTask = Task.Run(WriterLoopAsync, CancellationToken.None);
        }

        /// <summary>
        /// Жизненный цикл сессии клиента: чтение пакетов в цикле, пока соединение открыто.
        /// </summary>
        public async Task HandleClientAsync()
        {
            using (_client)
            await using (_stream)
            {
                byte[] headerBuffer = new byte[HeaderBufferSize];

                try
                {
                    while (!_sessionCts.Token.IsCancellationRequested)
                    {
                        await _stream.ReadExactlyAsync(headerBuffer, _sessionCts.Token);

                        if (!TryParseHeader(headerBuffer, out int headerLength, out int payloadLength))
                        {
                            if (headerLength == -1)
                            {
                                throw new InvalidDataException(
                                    $"Заголовок превышает {HeaderBufferSize} байт без разделителя.");
                            }
                            else 
                            {
                                // headerLength >= 0, но TryParseHeader вернул false
                                // Это ЗНАЧИТ разделитель найден, но перед ним мусор
                                throw new InvalidDataException(
                                    $"Невалидный размер пакета в заголовке: " +
                                    $"'{AnsiEncoding.GetString(headerBuffer, 0, headerLength)}'. Ожидается ASCII-число.");
                            }
                        }    
                        
                        // Валидный заголовок

                        if (payloadLength <= 0 || payloadLength > MaxPacketSize)
                        {
                            throw new InvalidDataException($"Недопустимый размер пакета: {payloadLength} байт.");
                        }

                        payloadLength += 1; //в коде клиента чата не учтен 0-й байт между prefix + #0 + AData

                        // Вычисляем, сколько байт занимает заголовок (строка цифр (#0 разделитель также входит в payload))
                        // int headerLength = zeroIndex;
                        int totalPacketLength = headerLength + payloadLength;
                        // -------------------------------------------------------------

                        // Выделяем память под весь пакет целиком (вместе с заголовком, его надо пересылать «как есть»)
                        var buffer = new RefCountedBuffer(ArrayPool<byte>.Shared.Rent(totalPacketLength), totalPacketLength);

                        try
                        {
                            var packetBuffer = buffer.Memory;
                            // В буфере лежит только часть пакета. Сначала забираем то, что есть...
                            headerBuffer.CopyTo(packetBuffer);
                            // ...и дочитываем оставшийся хвост пакета напрямую из сети
                            // Встроенный метод .NET сам сделает цикл, сдвиги и выбросит EndOfStreamException, если клиент отключится
                            await _stream.ReadExactlyAsync(packetBuffer[HeaderBufferSize..], _sessionCts.Token);
                            HandleAndRoutePacket(buffer);
                        }
                        finally
                        {
                            buffer.Release();
                        }
                    }
                }
                catch (OperationCanceledException)
                {
                    string ep = _client.Client?.RemoteEndPoint?.ToString() ?? "unknown";
                    if (_serverToken.IsCancellationRequested)
                        Log.Debug("[СЕССИЯ] Клиент {ClientIp} отключен из-за остановки сервера.", ep);
                    else
                        Log.Debug("[СЕССИЯ] Клиент {ClientIp} закрыт по инициативе сервера.", ep);
                }
                catch (EndOfStreamException)
                {
                    string ep = _client.Client?.RemoteEndPoint?.ToString() ?? "unknown";
                    Log.Debug("[СЕССИЯ] Клиент {ClientIp} штатно отключился.", ep);
                }
                catch (IOException)
                {
                    string ep = _client.Client?.RemoteEndPoint?.ToString() ?? "unknown";
                    Log.Debug("[СЕССИЯ] Потеряна связь с клиентом {ClientIp}.", ep);
                }
                catch (Exception ex)
                {
                    string ep = _client.Client?.RemoteEndPoint?.ToString() ?? "unknown";
                    Log.Warning(ex, "[СЕССИЯ] Ошибка при работе с клиентом {ClientIp}", ep);
                }
                finally
                {
                    Close();

                    // ждем остановки Writer
                    try { await _writerTask.ConfigureAwait(false); }
                    catch { /* уже залогировано */ }

                    _sessionCts.Dispose();
                }
            }
        }
        

        /// <summary>
        /// Маршрутизация
        /// </summary>
        private void HandleAndRoutePacket(RefCountedBuffer buffer)
        {
            ReadOnlyMemory<byte> packet = buffer.Memory;
            // Вызываем синхронный метод-помощник для парсинга префикса пакета
            if (!TryParsePrefix(packet.Span, out string curId,
                                out ReadOnlySpan<byte> marker, out string toUser))
            {
                Log.Warning("[СЕССИЯ] Битый пакет: не удалось разобрать структуру по маркерам #0.");
                return;
            }

            // Проверяем, авторизован ли уже этот конкретный клиент на сервере?
            if (ClientId == null)
            {
                // === ЭТАП АВТОРИЗАЦИИ ===
                // Согласно протоколу, имя авторизации берем из curId (отправитель)
                if (!_manager.AddConnection(curId, this))
                {
                    Log.Warning("[СЕССИЯ] ID '{CurId}' уже занят. Отключаем дубликат.", curId);
                    Close();
                    return;
                    // throw new InvalidDataException($"ID '{curId}' уже занят. Отключаем дубликат.");
                }
                ClientId = curId;
                Log.Debug("[СЕССИЯ] Клиент '{ClientId}' успешно авторизован по протоколу UniChat.", ClientId);
            }

            // === ЭТАП МАРШРУТИЗАЦИИ И ПЕРЕСЫЛКИ ===
            // Если команда в пакете равна "FORWARD"
            if (marker.SequenceEqual(ForwardMarker))
            {
                if (toUser == "*")
                {
                    // Если адресат * шлем всем
                    Log.Debug("[СЕССИЯ] {ClientId} -> ВСЕМ ({PacketLength} байт)", ClientId, packet.Length);
                    _manager.SendBroadcast(buffer);
                }
                else if (string.IsNullOrWhiteSpace(toUser))
                {
                    return;
                }
                else
                {
                    // Если указано конкретное имя — делаем точечную доставку получателю!
                    Log.Debug("[СЕССИЯ] {ClientId} -> для '{ToUser}' ({PacketLength} байт)", ClientId, toUser, packet.Length);
                    _manager.SendToClient(toUser, buffer);
                }
            }
            else
            {
                Log.Warning("[СЕССИЯ] Получена неизвестная команда от {ClientId}: {Marker}", ClientId, Convert.ToHexString(marker));
            }
        }


        // SendText(inttostr(length(AData) + length(prefix)) + prefix + #0 + AData);
        // prefix := #0 + CurID + #0'FORWARD'#0 + toUser + #0'UniChat'#0 + tmp;

        /// <summary>
        /// Синхронный парсер префикса. Выделяет куски в стеке, что безопасно в C# 12 вне async-методов.
        /// </summary>
        private static bool TryParsePrefix(
            ReadOnlySpan<byte> fullPacket, 
            out string curId, 
            out ReadOnlySpan<byte> marker, 
            out string toUser)
        {
            curId = string.Empty;
            marker = ReadOnlySpan<byte>.Empty;
            toUser = string.Empty;

            Span<int> pieceOffsets = stackalloc int[4];
            Span<int> pieceLengths = stackalloc int[4];

            int pieceCount = 0;
            int currentPos = 0;

            // Режем пакет по нулевым байтам (#0)
            while (currentPos < fullPacket.Length && pieceCount < 4)
            {
                int nextZero = fullPacket[currentPos..].IndexOf((byte)0);
                if (nextZero == -1)
                {
                    if (currentPos < fullPacket.Length)
                    {
                        pieceOffsets[pieceCount] = currentPos;
                        pieceLengths[pieceCount] = fullPacket.Length - currentPos;
                        pieceCount++;
                    }
                    break;
                }

                pieceOffsets[pieceCount] = currentPos;
                pieceLengths[pieceCount] = nextZero;
                pieceCount++;

                currentPos += nextZero + 1;
            }

            // Защита: для извлечения toUser нам нужно как минимум 4 куска (0, 1, 2, 3)
            if (pieceCount < 4) return false;

            // Извлекаем все куски из Span памяти по сохраненным индексам
            ReadOnlySpan<byte> curIdBytes = fullPacket.Slice(pieceOffsets[1], pieceLengths[1]);
            ReadOnlySpan<byte> toUserBytes = fullPacket.Slice(pieceOffsets[3], pieceLengths[3]);

            curId = AnsiEncoding.GetString(curIdBytes);
            toUser = AnsiEncoding.GetString(toUserBytes);

            marker = fullPacket.Slice(pieceOffsets[2], pieceLengths[2]);

            return true;
        }

        private static bool TryParseHeader(byte[] buffer, out int headerLength, out int payloadLength)
        {
            payloadLength = -1;
            ReadOnlySpan<byte> currentData = buffer.AsSpan();

            // Ищем нулевой байт
            headerLength = currentData.IndexOf((byte)0);
            if (headerLength == -1) return false;

            // Парсим размер из UTF8-байтов напрямую в int
            return Utf8Parser.TryParse(currentData[..headerLength], out payloadLength, out _);
        }

        // Владение буфером переходит каналу. Вызывающий больше НЕ должен Dispose-ить.
        public void EnqueuePacket(RefCountedBuffer buffer)
        {
            buffer.AddRef();
            if (_outgoing.Writer.TryWrite(buffer)) return;

            // не влезло
            buffer.Release();
            // если еще не закрыт, то закрываем и пишем лог
            if (Close())
            {
                Log.Warning("[СЕССИЯ] Очередь {ClientId} переполнена, клиент будет отключен", ClientId);
            }
        }

        private async Task WriterLoopAsync()
        {
            try
            {
                await foreach (var buffer in _outgoing.Reader.ReadAllAsync())
                {
                    try
                    {
                        await _stream.WriteAsync(buffer.Memory).ConfigureAwait(false);
                    }
                    catch (Exception ex)
                    {
                        Log.Warning(ex, "[СЕССИЯ] Ошибка отправки клиенту {ClientId}", ClientId);
                        break;   // дальше писать бессмысленно, соединение битое
                    }
                    finally
                    {
                        buffer.Release();   // владение буфера заканчивается здесь
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[СЕССИЯ] Writer упал для {ClientId}", ClientId);
            }
            finally
            {
                Close();

                int drained = 0;
                while (_outgoing.Reader.TryRead(out var buffer))
                {
                    buffer.Release();
                    drained++;
                }
                if (drained > 0)
                    Log.Warning("[СЕССИЯ] Writer аварийно слил {Count} пакетов для '{ClientId}'", drained, ClientId);
            }

            Log.Debug("[СЕССИЯ] Writer остановлен для '{ClientId}'", ClientId);
        }

        public bool Close()
        {
            if (Interlocked.Exchange(ref _closed, 1) == 1)
                return false;

            if (ClientId != null)
            {
                _manager.RemoveConnection(ClientId);
                Log.Debug("[СЕССИЯ] Клиент '{ClientId}' удален из менеджера.", ClientId);
            }

            // Говорим Writer'у: новых сообщений не будет, дорабатывай и выходи
            _outgoing.Writer.TryComplete();

            // Будим ридер, если он висит на ReadExactlyAsync
            _sessionCts.Cancel();
            return true;   // "я закрыл"
        }

    }

}
