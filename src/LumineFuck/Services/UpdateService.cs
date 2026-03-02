using Velopack;
using Velopack.Sources;

namespace LumineFuck.Services;

/// <summary>
/// Handles checking for updates and applying them via Velopack + GitHub Releases.
/// </summary>
public sealed class UpdateService
{
    // TODO: Update this to the actual GitHub repository owner/name
    private const string RepoUrl = "https://github.com/Nano191225/lumine-fuck";

    private readonly UpdateManager _updateManager;

    public event Action<string>? OnLog;
    public event Action<string>? OnUpdateAvailable;

    public string? LatestVersion { get; private set; }
    public bool IsUpdateAvailable { get; private set; }

    public UpdateService()
    {
        _updateManager = new UpdateManager(new GithubSource(RepoUrl, null, false));
    }

    /// <summary>
    /// Checks for updates in the background.
    /// </summary>
    public async Task<bool> CheckForUpdatesAsync()
    {
        try
        {
            var newVersion = await _updateManager.CheckForUpdatesAsync();
            if (newVersion != null)
            {
                LatestVersion = newVersion.TargetFullRelease.Version.ToString();
                IsUpdateAvailable = true;
                OnLog?.Invoke($"Update available: v{LatestVersion}");
                OnUpdateAvailable?.Invoke(LatestVersion);
                return true;
            }
            else
            {
                OnLog?.Invoke("No updates available.");
                return false;
            }
        }
        catch (Exception ex)
        {
            OnLog?.Invoke($"Update check failed: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Downloads and applies the latest update, then restarts.
    /// </summary>
    public async Task DownloadAndApplyAsync(Action<int>? progressCallback = null)
    {
        try
        {
            var newVersion = await _updateManager.CheckForUpdatesAsync();
            if (newVersion == null)
            {
                OnLog?.Invoke("No update to apply.");
                return;
            }

            OnLog?.Invoke("Downloading update...");
            await _updateManager.DownloadUpdatesAsync(newVersion, p => progressCallback?.Invoke(p));

            OnLog?.Invoke("Applying update and restarting...");
            _updateManager.ApplyUpdatesAndRestart(newVersion);
        }
        catch (Exception ex)
        {
            OnLog?.Invoke($"Update failed: {ex.Message}");
            throw;
        }
    }
}
