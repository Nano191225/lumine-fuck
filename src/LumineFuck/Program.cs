using Velopack;

namespace LumineFuck;

/// <summary>
/// Custom entry point so VelopackApp.Run() executes before ANY WPF initialization.
/// This is required for Velopack install/update/uninstall hooks to work correctly.
/// </summary>
public static class Program
{
    [STAThread]
    public static void Main(string[] args)
    {
        // Velopack MUST be the very first thing to run.
        // It handles --velopack-install / --velopack-updated / --velopack-uninstall hooks
        // and exits the process immediately when invoked by the updater.
        VelopackApp.Build().Run();

        var app = new App();
        app.InitializeComponent();
        app.Run();
    }
}
