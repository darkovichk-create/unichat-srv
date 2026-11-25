// Original UniChat server author: Sergey Rihmayer (s.rihmayer@mail.ru)

using System.Threading.Channels;
using Microsoft.Data.Sqlite;
using Serilog;

namespace UniChatServerd;

/// <summary>
/// Асинхронный журнал метаданных сессий, маршрутизации и ошибок.
/// Содержимое пользовательских сообщений никогда не передаётся этому классу.
/// </summary>
public sealed class AuditLog : BackgroundService
{
    private const int QueueCapacity = 8192;
    private const int BatchSize = 128;
    private static readonly TimeSpan Retention = TimeSpan.FromDays(20);
    private readonly string _databasePath;
    private readonly Channel<AuditEvent> _queue;
    private long _droppedEvents;

    public AuditLog(IConfiguration configuration)
    {
        string? configuredPath = configuration["audit-db"];
        if (!string.IsNullOrWhiteSpace(configuredPath))
        {
            _databasePath = Path.GetFullPath(configuredPath);
        }
        else if (OperatingSystem.IsWindows())
        {
            _databasePath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "UniChatServerd", "audit.db");
        }
        else
        {
            _databasePath = "/var/lib/unichatd/audit.db";
        }

        _queue = Channel.CreateBounded<AuditEvent>(new BoundedChannelOptions(QueueCapacity)
        {
            SingleReader = true,
            SingleWriter = false,
            FullMode = BoundedChannelFullMode.Wait,
            AllowSynchronousContinuations = false
        });
    }

    public void Record(
        string eventType,
        string? sessionId = null,
        string? clientId = null,
        string? remoteIp = null,
        string? targetId = null,
        long? durationMs = null,
        int? packetBytes = null,
        string? result = null,
        string? details = null)
    {
        var item = new AuditEvent(
            DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            eventType,
            sessionId,
            clientId,
            remoteIp,
            targetId,
            durationMs,
            packetBytes,
            result,
            Limit(details, 512));

        if (_queue.Writer.TryWrite(item))
            return;

        long dropped = Interlocked.Increment(ref _droppedEvents);
        if (dropped == 1 || dropped % 100 == 0)
            Log.Warning("Audit queue is full; dropped {DroppedEvents} audit events", dropped);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            SqliteConnection? connection = null;
            var pending = new List<AuditEvent>(BatchSize);
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(_databasePath)!);
                if (!OperatingSystem.IsWindows())
                    File.SetUnixFileMode(Path.GetDirectoryName(_databasePath)!,
                        UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

                var connectionString = new SqliteConnectionStringBuilder
                {
                    DataSource = _databasePath,
                    Mode = SqliteOpenMode.ReadWriteCreate,
                    Cache = SqliteCacheMode.Shared,
                    Pooling = true,
                    DefaultTimeout = 5
                }.ToString();

                connection = new SqliteConnection(connectionString);
                await connection.OpenAsync(stoppingToken).ConfigureAwait(false);
                await InitializeDatabaseAsync(connection, stoppingToken).ConfigureAwait(false);

                if (!OperatingSystem.IsWindows())
                    File.SetUnixFileMode(_databasePath, UnixFileMode.UserRead | UnixFileMode.UserWrite);

                Log.Information("Audit database opened at {DatabasePath}; retention is {RetentionDays} days",
                    _databasePath, (int)Retention.TotalDays);

                await ConsumeQueueAsync(connection, pending, stoppingToken).ConfigureAwait(false);
                break;
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                Log.Error(ex,
                    "Audit database is unavailable; retrying in 5 seconds. TCP relay remains operational.");

                // If a batch failed before commit, put it back into the bounded queue for retry.
                foreach (var item in pending)
                {
                    if (!_queue.Writer.TryWrite(item))
                    {
                        long dropped = Interlocked.Increment(ref _droppedEvents);
                        if (dropped == 1 || dropped % 100 == 0)
                            Log.Warning("Audit queue is full while retrying; dropped {DroppedEvents} events", dropped);
                    }
                }
                pending.Clear();

                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    break;
                }
            }
            finally
            {
                if (connection is not null)
                {
                    if (stoppingToken.IsCancellationRequested &&
                        connection.State == System.Data.ConnectionState.Open)
                    {
                        try
                        {
                            while (_queue.Reader.TryRead(out var item))
                                pending.Add(item);

                            if (pending.Count > 0)
                                await InsertBatchAsync(connection, pending, CancellationToken.None).ConfigureAwait(false);
                        }
                        catch (Exception ex)
                        {
                            Log.Error(ex, "Could not flush the final audit batch during shutdown");
                        }
                    }

                    await connection.DisposeAsync().ConfigureAwait(false);
                }
            }
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        _queue.Writer.TryComplete();
        await base.StopAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task InitializeDatabaseAsync(SqliteConnection connection, CancellationToken ct)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = """
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=NORMAL;
            PRAGMA busy_timeout=5000;
            PRAGMA auto_vacuum=INCREMENTAL;
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp_utc INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                session_id TEXT NULL,
                client_id TEXT NULL,
                remote_ip TEXT NULL,
                target_id TEXT NULL,
                duration_ms INTEGER NULL,
                packet_bytes INTEGER NULL,
                result TEXT NULL,
                details TEXT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_audit_timestamp ON audit_events(timestamp_utc);
            CREATE INDEX IF NOT EXISTS ix_audit_client_timestamp ON audit_events(client_id, timestamp_utc);
            CREATE INDEX IF NOT EXISTS ix_audit_session_timestamp ON audit_events(session_id, timestamp_utc);
            """;
        await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        await CleanupOldEventsAsync(connection, ct).ConfigureAwait(false);
    }

    private async Task ConsumeQueueAsync(
        SqliteConnection connection,
        List<AuditEvent> pending,
        CancellationToken ct)
    {
        var nextCleanup = DateTimeOffset.UtcNow.AddHours(1);

        while (await _queue.Reader.WaitToReadAsync(ct).ConfigureAwait(false))
        {
            pending.Clear();
            while (pending.Count < BatchSize && _queue.Reader.TryRead(out var item))
                pending.Add(item);

            if (pending.Count > 0)
            {
                await InsertBatchAsync(connection, pending, ct).ConfigureAwait(false);
                pending.Clear();
            }

            if (DateTimeOffset.UtcNow >= nextCleanup)
            {
                await CleanupOldEventsAsync(connection, ct).ConfigureAwait(false);
                nextCleanup = DateTimeOffset.UtcNow.AddHours(1);
            }
        }
    }

    private static async Task InsertBatchAsync(
        SqliteConnection connection,
        IReadOnlyList<AuditEvent> events,
        CancellationToken ct)
    {
        await using var transaction = await connection.BeginTransactionAsync(ct).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.Transaction = (SqliteTransaction)transaction;
        command.CommandText = """
            INSERT INTO audit_events
                (timestamp_utc, event_type, session_id, client_id, remote_ip,
                 target_id, duration_ms, packet_bytes, result, details)
            VALUES
                ($timestamp, $type, $session, $client, $ip,
                 $target, $duration, $bytes, $result, $details);
            """;

        var timestamp = command.Parameters.Add("$timestamp", SqliteType.Integer);
        var type = command.Parameters.Add("$type", SqliteType.Text);
        var session = command.Parameters.Add("$session", SqliteType.Text);
        var client = command.Parameters.Add("$client", SqliteType.Text);
        var ip = command.Parameters.Add("$ip", SqliteType.Text);
        var target = command.Parameters.Add("$target", SqliteType.Text);
        var duration = command.Parameters.Add("$duration", SqliteType.Integer);
        var bytes = command.Parameters.Add("$bytes", SqliteType.Integer);
        var result = command.Parameters.Add("$result", SqliteType.Text);
        var details = command.Parameters.Add("$details", SqliteType.Text);

        foreach (var item in events)
        {
            timestamp.Value = item.TimestampUtc;
            type.Value = item.EventType;
            session.Value = DbValue(item.SessionId);
            client.Value = DbValue(item.ClientId);
            ip.Value = DbValue(item.RemoteIp);
            target.Value = DbValue(item.TargetId);
            duration.Value = DbValue(item.DurationMs);
            bytes.Value = DbValue(item.PacketBytes);
            result.Value = DbValue(item.Result);
            details.Value = DbValue(item.Details);
            await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }

        await transaction.CommitAsync(ct).ConfigureAwait(false);
    }

    private static async Task CleanupOldEventsAsync(SqliteConnection connection, CancellationToken ct)
    {
        long cutoff = DateTimeOffset.UtcNow.Subtract(Retention).ToUnixTimeMilliseconds();
        await using var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM audit_events WHERE timestamp_utc < $cutoff;";
        command.Parameters.AddWithValue("$cutoff", cutoff);
        int deleted = await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);

        await using var maintenance = connection.CreateCommand();
        maintenance.CommandText = "PRAGMA incremental_vacuum(200); PRAGMA wal_checkpoint(PASSIVE);";
        await maintenance.ExecuteNonQueryAsync(ct).ConfigureAwait(false);

        if (deleted > 0)
            Log.Information("Audit retention cleanup removed {DeletedEvents} events older than {RetentionDays} days",
                deleted, (int)Retention.TotalDays);
    }

    private static object DbValue(object? value) => value ?? DBNull.Value;

    private static string? Limit(string? value, int maxLength) =>
        value is null ? null : value.Length <= maxLength ? value : value[..maxLength];

    private sealed record AuditEvent(
        long TimestampUtc,
        string EventType,
        string? SessionId,
        string? ClientId,
        string? RemoteIp,
        string? TargetId,
        long? DurationMs,
        int? PacketBytes,
        string? Result,
        string? Details);
}
