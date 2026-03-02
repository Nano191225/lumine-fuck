using System.Windows;
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

        base.OnStartup(e);
    }
}

