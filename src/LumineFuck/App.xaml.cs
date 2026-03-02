using System.Diagnostics;
using System.Security.Principal;
using System.Windows;
using Microsoft.Toolkit.Uwp.Notifications;
using Microsoft.Win32;
using Velopack;

namespace LumineFuck;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        // Velopack must be initialized before anything else
        try
        {
            VelopackApp.Build().Run();
        }
        catch
        {
            // Not installed via Velopack (e.g. debug mode) — ignore
        }

        // Register toast notification COM activator (required for unpackaged Win32 apps)
        try { ToastNotificationManagerCompat.OnActivated += _ => { }; }
        catch { }

        // Require administrator privileges — re-launch with UAC elevation if needed
        if (!IsRunningAsAdministrator())
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule!.FileName,
                    UseShellExecute = true,
                    Verb = "runas", // Triggers UAC prompt
                    Arguments = string.Join(" ", e.Args)
                };
                Process.Start(psi);
            }
            catch
            {
                // User cancelled UAC prompt
            }
            Shutdown();
            return;
        }

        // Check Npcap is installed (required for UDP packet capture)
        if (!IsNpcapInstalled())
        {
            var result = MessageBox.Show(
                "Npcap is required for UDP traffic monitoring (same driver as Wireshark).\n\n" +
                "Click OK to open the Npcap download page, then restart LumineFuck after installing.\n\n" +
                "https://npcap.com/#download",
                "Npcap Required",
                MessageBoxButton.OKCancel,
                MessageBoxImage.Warning);

            if (result == MessageBoxResult.OK)
            {
                Process.Start(new ProcessStartInfo("https://npcap.com/#download") { UseShellExecute = true });
            }

            Shutdown();
            return;
        }

        base.OnStartup(e);
    }

    private static bool IsRunningAsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static bool IsNpcapInstalled()
    {
        // Check Npcap service key — not subject to WOW64 registry redirection
        using var services = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var npcapService = services.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\npcap");
        if (npcapService != null) return true;

        // Fallback: check SOFTWARE\Npcap in 64-bit hive
        using var software = services.OpenSubKey(@"SOFTWARE\Npcap");
        return software != null;
    }
}

