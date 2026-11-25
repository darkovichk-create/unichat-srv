// Original UniChat server author: Sergey Rihmayer (s.rihmayer@mail.ru)

using Serilog;
using System;
using System.Buffers;
using System.Collections.Concurrent;

namespace UniChatServerd
{
    internal class ConnectionManager
    {
        // Потокобезопасный словарь активных подключений.
        private readonly ConcurrentDictionary<string, ClientConnection> _connections = new();

        public bool AddConnection(string id, ClientConnection connection)
        {
            return _connections.TryAdd(id, connection);
        }

        public void RemoveConnection(string id, ClientConnection connection)
        {
            // Не позволяем старой закрывающейся сессии удалить новую сессию
            // с тем же ClientId после быстрого reconnect.
            ((ICollection<KeyValuePair<string, ClientConnection>>)_connections)
                .Remove(new KeyValuePair<string, ClientConnection>(id, connection));
        }

        // Отправка конкретному клиенту по ID. true означает постановку в очередь.
        public bool SendToClient(string targetId, RefCountedBuffer buffer)
        {
            if (_connections.TryGetValue(targetId, out var connection))
                return connection.EnqueuePacket(buffer);

            Log.Debug("[МЕНЕДЖЕР] Получатель '{TargetId}' не найден, пакет отброшен.", targetId);
            return false;
        }

        // Рассылка всем. Возвращает количество успешно поставленных в очередь получателей.
        public int SendBroadcast(RefCountedBuffer buffer)
        {
            int queued = 0;
            foreach (var connection in _connections.Values)
            {
                if (connection.EnqueuePacket(buffer))
                    queued++;
            }

            return queued;
        }
    }
}
