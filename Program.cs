// author Sergey Rihmayer

using Microsoft.Extensions.Hosting.WindowsServices;
using Serilog;
using Serilog.Events;
using System.Text;

namespace UniChatServerd
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

            var builder = Host.CreateApplicationBuilder(args);
            builder.Configuration.AddCommandLine(args);
            builder.Services.AddSingleton<AuditLog>();
            builder.Services.AddHostedService(sp => sp.GetRequiredService<AuditLog>());
            builder.Services.AddHostedService<TcpServerListener>();

            if (OperatingSystem.IsWindows())
            {
                builder.Services.AddWindowsService(options =>
                {
                    options.ServiceName = "UniChatServerd";
                });
            }
            else if (OperatingSystem.IsLinux())
            {
                builder.Services.AddSystemd();
            }

            string logLevelStr = builder.Configuration["log-level"] ?? "Information";
            if (!Enum.TryParse<LogEventLevel>(logLevelStr, true, out var baseLevel))
            {
                baseLevel = LogEventLevel.Information; // default
            }

            var loggerConfig = new LoggerConfiguration()
                .MinimumLevel.Is(baseLevel)
                .MinimumLevel.Override("Microsoft", LogEventLevel.Warning) // Глушим системный спам Microsoft
                .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj}{NewLine}{Exception}");

            if (OperatingSystem.IsWindows() && WindowsServiceHelpers.IsWindowsService())
            {
                string logPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "UniChatServerd", "logs", "log-.txt"
                );

                loggerConfig.WriteTo.File(
                    path: logPath,
                    rollingInterval: RollingInterval.Day,
                    retainedFileCountLimit: 14,
                    outputTemplate: "[{Timestamp:yyyy-MM-dd HH:mm:ss} {Level:u3}] {Message:lj}{NewLine}{Exception}"
                );
            }

            Log.Logger = loggerConfig.CreateLogger();

            // builder.Logging.AddConsole();

            try
            {
                var host = builder.Build();
                host.Run();
            }
            catch (Exception ex)
            {
                Log.Fatal(ex, "Служба упала при запуске");
            }
            finally
            {
                Log.CloseAndFlush();
            }
        }
    }
}
