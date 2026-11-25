// author Sergey Rihmayer

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
        private readonly AuditLog _auditLog;
        private readonly string _sessionId = Guid.NewGuid().ToString("N");
        private readonly string _remoteIp;
        private readonly DateTimeOffset _connectedAtUtc = DateTimeOffset.UtcNow;
        private const int HeaderBufferSize = 16;
        // Максимум байт после заголовка размера, включая разделитель между prefix и AData.
        private const int MaxPacketSize = 128 * 1024;
        private static readonly Encoding AnsiEncoding = Encoding.GetEncoding(1251);

        public string? ClientId { get; private set; }

        private static ReadOnlySpan<byte> ForwardMarker => "FORWARD"u8;

        private readonly Channel<RefCountedBuffer> _outgoing;
        private readonly Task _writerTask;
        private int _closed;

        public ClientConnection(TcpClient client, ConnectionManager manager, CancellationToken serverToken, AuditLog auditLog)
        {
            _client = client;
            _auditLog = auditLog;
            _remoteIp = client.Client.RemoteEndPoint is IPEndPoint endpoint
                ? endpoint.Address.ToString()
                : "unknown";
            _auditLog.Record("session_open", _sessionId, remoteIp: _remoteIp);
            _manager = manager;
            _serverToken = serverToken;
            _sessionCts = CancellationTokenSource.CreateLinkedTokenSource(serverToken);
            _stream = client.GetStream();

            _outgoing = Channel.CreateBounded<RefCountedBuffer>(
                new BoundedChannelOptions(capacity: 256)
                {
                    SingleReader = true,
                    SingleWriter = false,
                    FullMode = BoundedChannelFullMode.Wait,
                    AllowSynchronousContinuations = false
                });

            _writerTask = Task.Run(WriterLoopAsync, CancellationToken.None);
        }

        /// <summary>
        /// Читает переменный по длине заголовок: ASCII-размер, затем нулевой байт.
        /// ReadExactlyAsync на фиксированные 16 байт здесь использовать нельзя:
        /// короткий TCP-пакет не обязан заполнять этот буфер.
        /// </summary>
        private async ValueTask<(int HeaderLength, int AdvertisedPayloadLength)> ReadHeaderAsync(
            byte[] headerBuffer,
            CancellationToken cancellationToken)
        {
            int headerLength = 0;

            while (headerLength < HeaderBufferSize)
            {
                int bytesRead = await _stream.ReadAsync(
                    headerBuffer.AsMemory(headerLength, 1),
                    cancellationToken).ConfigureAwait(false);

                if (bytesRead == 0)
                {
                    if (headerLength == 0)
                        throw new EndOfStreamException();

                    throw new InvalidDataException("Соединение закрыто внутри заголовка пакета.");
                }

                if (headerBuffer[headerLength] == 0)
                {
                    if (headerLength == 0 ||
                        !Utf8Parser.TryParse(
                            headerBuffer.AsSpan(0, headerLength),
                            out int payloadLength,
                            out int consumed) ||
                        consumed != headerLength ||
                        payloadLength <= 0)
                    {
                        throw new InvalidDataException("Некорректная длина пакета в заголовке.");
                    }

                    return (headerLength, payloadLength);
                }

                headerLength++;
            }

            throw new InvalidDataException(
                $"Заголовок превышает допустимые {HeaderBufferSize - 1} байт без разделителя.");
        }

        /// <summary>
        /// Жизненный цикл сессии клиента: чтение и маршрутизация пакетов до отключения.
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
                        var (headerLength, advertisedPayloadLength) =
                            await ReadHeaderAsync(headerBuffer, _sessionCts.Token).ConfigureAwait(false);

                        // Первый NUL префикса одновременно завершает числовой заголовок;
                        // оставшиеся prefix + разделитель + AData занимают advertisedPayloadLength.
                        int wirePayloadLength = advertisedPayloadLength;
                        if (wirePayloadLength > MaxPacketSize)
                        {
                            throw new InvalidDataException(
                                $"Размер пакета превышает лимит {MaxPacketSize} байт.");
                        }

                        int headerBytesLength = headerLength + 1; // цифры + #0
                        int totalPacketLength = checked(headerBytesLength + wirePayloadLength);

                        var buffer = new RefCountedBuffer(
                            ArrayPool<byte>.Shared.Rent(totalPacketLength),
                            totalPacketLength);

                        try
                        {
                            var packetBuffer = buffer.Memory;
                            headerBuffer.AsMemory(0, headerBytesLength).CopyTo(packetBuffer);

                            await _stream.ReadExactlyAsync(
                                packetBuffer[headerBytesLength..],
                                _sessionCts.Token).ConfigureAwait(false);

                            HandleAndRoutePacket(buffer, headerBytesLength);
                        }
                        finally
                        {
                            buffer.Release();
                        }
                    }
                }
                catch (OperationCanceledException)
                {
                    string reason = _serverToken.IsCancellationRequested ? "server_shutdown" : "cancelled";
                    _auditLog.Record("session_cancelled", _sessionId, ClientId, _remoteIp, result: reason);
                    Log.Debug("[СЕССИЯ] Клиент {ClientIp} отключен: {Reason}.", _remoteIp, reason);
                    Close(reason);
                }
                catch (EndOfStreamException)
                {
                    Log.Debug("[СЕССИЯ] Клиент {ClientIp} штатно отключился.", _remoteIp);
                    Close("peer_closed");
                }
                catch (IOException ex)
                {
                    _auditLog.Record("transport_error", _sessionId, ClientId, _remoteIp,
                        result: "read_failed", details: ex.Message);
                    Log.Debug(ex, "[СЕССИЯ] Потеряна связь с клиентом {ClientIp}.", _remoteIp);
                    Close("network_error");
                }
                catch (Exception ex)
                {
                    _auditLog.Record("session_error", _sessionId, ClientId, _remoteIp,
                        result: "unhandled_exception", details: ex.Message);
                    Log.Warning(ex, "[СЕССИЯ] Ошибка при работе с клиентом {ClientIp}", _remoteIp);
                    Close("session_error");
                }
                finally
                {
                    Close();

                    try { await _writerTask.ConfigureAwait(false); }
                    catch { /* ошибка уже обработана в WriterLoopAsync */ }

                    _sessionCts.Dispose();
                }
            }
        }

        /// <summary>
        /// Маршрутизация. Пакеты пересылаются без изменения содержимого,
        /// поэтому серверу не требуется разбирать текст или бинарные данные AData.
        /// </summary>
        private void HandleAndRoutePacket(RefCountedBuffer buffer, int headerBytesLength)
        {
            ReadOnlyMemory<byte> packet = buffer.Memory;

            if (!TryParsePrefix(packet.Span[headerBytesLength..], out string curId,
                                out ReadOnlySpan<byte> marker, out string toUser))
            {
                Log.Warning("[СЕССИЯ] Битый пакет: не удалось разобрать структуру по маркерам #0.");
                _auditLog.Record("protocol_error", _sessionId, ClientId, _remoteIp,
                    packetBytes: packet.Length, result: "invalid_prefix");
                return;
            }

            if (string.IsNullOrWhiteSpace(curId))
            {
                Log.Warning("[СЕССИЯ] Получен пакет с пустым ID отправителя.");
                _auditLog.Record("protocol_error", _sessionId, remoteIp: _remoteIp,
                    packetBytes: packet.Length, result: "empty_client_id");
                Close("protocol_error");
                return;
            }

            // Первый пакет регистрирует соединение. Во всех последующих пакетах
            // отправитель обязан совпадать с ID, закреплённым за TCP-соединением.
            if (ClientId == null)
            {
                if (!_manager.AddConnection(curId, this))
                {
                    Log.Warning("[СЕССИЯ] ID '{CurId}' уже занят. Отключаем дубликат.", curId);
                    _auditLog.Record("protocol_error", _sessionId, curId, _remoteIp,
                        packetBytes: packet.Length, result: "duplicate_client_id");
                    Close("duplicate_client_id");
                    return;
                }

                ClientId = curId;
                _auditLog.Record("client_connected", _sessionId, ClientId, _remoteIp, result: "registered");
                Log.Debug("[СЕССИЯ] Клиент '{ClientId}' успешно авторизован по протоколу UniChat.", ClientId);
            }
            else if (!string.Equals(curId, ClientId, StringComparison.Ordinal))
            {
                Log.Warning(
                    "[СЕССИЯ] Клиент '{ClientId}' прислал пакет с чужим ID '{CurId}'. Соединение закрывается.",
                    ClientId, curId);
                _auditLog.Record("protocol_error", _sessionId, ClientId, _remoteIp,
                    packetBytes: packet.Length, result: "client_id_mismatch", details: curId);
                Close("client_id_mismatch");
                return;
            }

            if (marker.SequenceEqual(ForwardMarker))
            {
                if (toUser == "*")
                {
                    int recipients = _manager.SendBroadcast(buffer);
                    _auditLog.Record("message_routed", _sessionId, ClientId, _remoteIp,
                        targetId: "*", packetBytes: packet.Length, result: "broadcast",
                        details: $"queued_recipients={recipients}");
                    Log.Debug("[СЕССИЯ] {ClientId} -> ВСЕМ ({PacketLength} байт), получателей: {Recipients}",
                        ClientId, packet.Length, recipients);
                }
                else if (!string.IsNullOrWhiteSpace(toUser))
                {
                    bool queued = _manager.SendToClient(toUser, buffer);
                    _auditLog.Record("message_routed", _sessionId, ClientId, _remoteIp,
                        targetId: toUser, packetBytes: packet.Length,
                        result: queued ? "queued" : "recipient_offline");
                    Log.Debug("[СЕССИЯ] {ClientId} -> для '{ToUser}' ({PacketLength} байт), результат: {Result}",
                        ClientId, toUser, packet.Length, queued ? "queued" : "recipient_offline");
                }
            }
            else
            {
                string markerHex = Convert.ToHexString(marker);
                Log.Warning("[СЕССИЯ] Получена неизвестная команда от {ClientId}: {Marker}",
                    ClientId, markerHex);
                _auditLog.Record("protocol_error", _sessionId, ClientId, _remoteIp,
                    packetBytes: packet.Length, result: "unknown_command", details: markerHex);
            }
        }

        /// <summary>
        /// Извлекает ClientId, команду и адресата из начала префикса.
        /// Остальная часть пакета остаётся непрозрачной и пересылается как есть.
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

            while (currentPos < fullPacket.Length && pieceCount < 4)
            {
                int nextZero = fullPacket[currentPos..].IndexOf((byte)0);
                if (nextZero == -1)
                {
                    pieceOffsets[pieceCount] = currentPos;
                    pieceLengths[pieceCount] = fullPacket.Length - currentPos;
                    pieceCount++;
                    break;
                }

                pieceOffsets[pieceCount] = currentPos;
                pieceLengths[pieceCount] = nextZero;
                pieceCount++;
                currentPos += nextZero + 1;
            }

            if (pieceCount < 3)
                return false;

            ReadOnlySpan<byte> curIdBytes = fullPacket.Slice(pieceOffsets[0], pieceLengths[0]);
            ReadOnlySpan<byte> toUserBytes = fullPacket.Slice(pieceOffsets[2], pieceLengths[2]);

            curId = AnsiEncoding.GetString(curIdBytes);
            toUser = AnsiEncoding.GetString(toUserBytes);
            marker = fullPacket.Slice(pieceOffsets[1], pieceLengths[1]);

            return true;
        }

        // SendText(IntToStr(Length(AData) + Length(prefix)) + prefix + #0 + AData);
        // prefix := #0 + CurID + #0 + 'FORWARD' + #0 + toUser + #0 + 'UniChat' + #0 + tmp;

        /// <summary>
        /// Владение буфером переходит каналу. Вызывающий больше не освобождает эту ссылку.
        /// </summary>
        public bool EnqueuePacket(RefCountedBuffer buffer)
        {
            buffer.AddRef();

            if (_outgoing.Writer.TryWrite(buffer))
                return true;

            buffer.Release();
            _auditLog.Record("queue_overflow", _sessionId, ClientId, _remoteIp,
                packetBytes: buffer.Length, result: "client_disconnected");
            if (Close("outgoing_queue_full"))
                Log.Warning("[СЕССИЯ] Очередь {ClientId} переполнена, клиент будет отключен", ClientId);
            return false;
        }

        private async Task WriterLoopAsync()
        {
            try
            {
                await foreach (var buffer in _outgoing.Reader.ReadAllAsync(_sessionCts.Token))
                {
                    try
                    {
                        await _stream.WriteAsync(buffer.Memory, _sessionCts.Token).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) when (_sessionCts.IsCancellationRequested)
                    {
                        break;
                    }
                    catch (Exception ex)
                    {
                        _auditLog.Record("transport_error", _sessionId, ClientId, _remoteIp,
                            result: "write_failed", details: ex.Message);
                        Log.Warning(ex, "[СЕССИЯ] Ошибка отправки клиенту {ClientId}", ClientId);
                        Close("send_error");
                        break;
                    }
                    finally
                    {
                        buffer.Release();
                    }
                }
            }
            catch (OperationCanceledException) when (_sessionCts.IsCancellationRequested)
            {
                // Штатное завершение сессии.
            }
            catch (Exception ex)
            {
                _auditLog.Record("session_error", _sessionId, ClientId, _remoteIp,
                    result: "writer_failed", details: ex.Message);
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
                    Log.Debug("[СЕССИЯ] Writer освободил {Count} ожидающих пакетов для '{ClientId}'",
                        drained, ClientId);
            }

            Log.Debug("[СЕССИЯ] Writer остановлен для '{ClientId}'", ClientId);
        }

        public bool Close(string reason = "closed")
        {
            if (Interlocked.Exchange(ref _closed, 1) == 1)
                return false;

            if (ClientId != null)
            {
                _manager.RemoveConnection(ClientId, this);
                Log.Debug("[СЕССИЯ] Клиент '{ClientId}' удален из менеджера.", ClientId);
            }

            long durationMs = Math.Max(0, (long)(DateTimeOffset.UtcNow - _connectedAtUtc).TotalMilliseconds);
            _auditLog.Record("session_closed", _sessionId, ClientId, _remoteIp,
                durationMs: durationMs, result: reason);

            _outgoing.Writer.TryComplete();
            _sessionCts.Cancel();

            // Прерываем в том числе зависшую сетевую запись; Dispose повторно безопасен.
            _client.Dispose();
            return true;
        }
    }
}
