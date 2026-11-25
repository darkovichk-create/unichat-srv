// Original UniChat server author: Sergey Rihmayer (s.rihmayer@mail.ru)

using Serilog;
using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Threading.Tasks;

namespace UniChatServerd
{
    internal class ConnectionManager
    {

        // Потокобезопасный словарь активных подключений
        private readonly ConcurrentDictionary<string, ClientConnection> _connections = new();

        public bool AddConnection(string id, ClientConnection connection)
        {
            return _connections.TryAdd(id, connection);
        }

        public void RemoveConnection(string id)
        {
            _connections.TryRemove(id, out _);
        }

        // Отправка конкретному клиенту по ID
        public void SendToClient(string targetId, RefCountedBuffer buffer)
        {
            if (_connections.TryGetValue(targetId, out var connection))
            {
                connection.EnqueuePacket(buffer);
            }
            else
            {
                Log.Debug("[МЕНЕДЖЕР] Получатель '{TargetId}' не найден, пакет отброшен.", targetId);
            }
        }

        // Рассылка всем
        public void SendBroadcast(RefCountedBuffer buffer)
        {
            foreach (var connection in _connections.Values)
            {
                connection.EnqueuePacket(buffer);
            }
        }

    }


}
