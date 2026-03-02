using System.Collections.ObjectModel;
using System.Net;
using System.Windows;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using LumineFuck.Core;
using LumineFuck.Models;
using LumineFuck.Services;

namespace LumineFuck.ViewModels;

public partial class MainViewModel : ObservableObject, IDisposable
{
    private readonly ConnectionMonitor _connectionMonitor;
    private readonly DnsResolver _dnsResolver;
    private readonly FirewallManager _firewallManager;
    private readonly BlockList _blockList;
    private readonly UpdateService _updateService;
    private readonly Dispatcher _dispatcher;
    private CancellationTokenSource? _processingCts;
    private Task? _processingTask;

    // --- Observable Properties ---

    [ObservableProperty]
    private bool _isEnabled;

    [ObservableProperty]
    private string _statusText = "Stopped";

    [ObservableProperty]
    private string _statusColor = "#FF6B6B"; // Red

    [ObservableProperty]
    private int _blockedCount;

    [ObservableProperty]
    private int _scannedCount;

    [ObservableProperty]
    private int _domainCount;

    [ObservableProperty]
    private string _appVersion = "v0.1.0";

    [ObservableProperty]
    private bool _isUpdateAvailable;

    [ObservableProperty]
    private string _updateVersionText = "";

    [ObservableProperty]
    private int _updateProgress;

    [ObservableProperty]
    private bool _isUpdating;

    public ObservableCollection<BlockedEntry> BlockedEntries { get; } = new();
    public ObservableCollection<string> LogEntries { get; } = new();

    // --- Constructor ---

    public MainViewModel()
    {
        _dispatcher = Application.Current.Dispatcher;

        _connectionMonitor = new ConnectionMonitor();
        _dnsResolver = new DnsResolver();
        _firewallManager = new FirewallManager();
        _blockList = new BlockList();
        _updateService = new UpdateService();

        // Wire up logging
        _connectionMonitor.OnLog += AddLog;
        _dnsResolver.OnLog += AddLog;
        _firewallManager.OnLog += AddLog;
        _blockList.OnLog += AddLog;
        _updateService.OnLog += AddLog;

        // Load settings
        _blockList.Load();
        DomainCount = _blockList.Domains.Count + _blockList.BlockedIps.Count;
        BlockedCount = _firewallManager.BlockedCount;

        // Get version from assembly
        var version = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
        if (version != null)
            AppVersion = $"v{version.Major}.{version.Minor}.{version.Build}";

        // Check for updates in background
        _ = CheckForUpdatesAsync();
    }

    // --- Commands ---

    partial void OnIsEnabledChanged(bool value)
    {
        if (value)
            StartProtection();
        else
            StopProtection();
    }

    [RelayCommand]
    private void ToggleProtection()
    {
        IsEnabled = !IsEnabled;
    }

    [RelayCommand]
    private void ClearLog()
    {
        _dispatcher.Invoke(() =>
        {
            BlockedEntries.Clear();
            LogEntries.Clear();
        });
    }

    [RelayCommand]
    private void ClearAllRules()
    {
        _firewallManager.UnblockAll();
        _connectionMonitor.ClearCache();
        _dnsResolver.ClearCache();
        BlockedCount = 0;
        ScannedCount = 0;
        _dispatcher.Invoke(() => BlockedEntries.Clear());
        AddLog("All firewall rules cleared and caches reset.");
    }

    [RelayCommand]
    private void OpenDomainManager()
    {
        var window = new Views.DomainListWindow(_blockList);
        window.Owner = Application.Current.MainWindow;
        window.ShowDialog();
        DomainCount = _blockList.Domains.Count + _blockList.BlockedIps.Count;
    }

    [RelayCommand]
    private async Task CheckForUpdatesAsync()
    {
        bool available = await _updateService.CheckForUpdatesAsync();
        if (available)
        {
            IsUpdateAvailable = true;
            UpdateVersionText = $"Update available: v{_updateService.LatestVersion}";
        }
    }

    [RelayCommand]
    private async Task ApplyUpdateAsync()
    {
        try
        {
            IsUpdating = true;
            await _updateService.DownloadAndApplyAsync(progress =>
            {
                _dispatcher.Invoke(() => UpdateProgress = progress);
            });
        }
        catch (Exception ex)
        {
            AddLog($"Update error: {ex.Message}");
            IsUpdating = false;
        }
    }

    // --- Protection Logic ---

    private void StartProtection()
    {
        _processingCts = new CancellationTokenSource();
        _connectionMonitor.Start();
        _processingTask = Task.Run(() => ProcessNewIpsAsync(_processingCts.Token));

        StatusText = "Active — Monitoring";
        StatusColor = "#51CF66"; // Green
        AddLog("Protection enabled.");
    }

    private void StopProtection()
    {
        _connectionMonitor.Stop();
        _processingCts?.Cancel();
        _processingTask = null;

        StatusText = "Stopped";
        StatusColor = "#FF6B6B"; // Red
        AddLog("Protection disabled.");
    }

    private async Task ProcessNewIpsAsync(CancellationToken ct)
    {
        // Process IPs with bounded parallelism for fast rDNS resolution
        const int maxParallel = 16;
        var semaphore = new SemaphoreSlim(maxParallel, maxParallel);
        var activeTasks = new List<Task>();

        try
        {
            await foreach (var ip in _connectionMonitor.NewIpReader.ReadAllAsync(ct))
            {
                await semaphore.WaitAsync(ct);

                var task = Task.Run(async () =>
                {
                    try
                    {
                        await ProcessSingleIpAsync(ip);
                    }
                    catch (Exception ex)
                    {
                        AddLog($"Task error for {ip}: {ex.GetType().Name}: {ex.Message}");
                    }
                    finally
                    {
                        semaphore.Release();
                    }
                }, CancellationToken.None); // Don't pass ct here — we handle cancellation in the foreach

                // Remove completed tasks periodically
                activeTasks.Add(task);
                activeTasks.RemoveAll(t => t.IsCompleted);
            }
        }
        catch (OperationCanceledException) { /* expected on stop */ }

        // Wait for remaining tasks to complete
        if (activeTasks.Count > 0)
            await Task.WhenAll(activeTasks).ConfigureAwait(false);
    }

    private async Task ProcessSingleIpAsync(IPAddress ip)
    {
        _dispatcher.Invoke(() => ScannedCount++);

        // 1. Check IP-based block list first (fast, no DNS needed)
        if (_blockList.MatchesBlockedIp(ip))
        {
            string matchedRule = _blockList.GetMatchedIpRule(ip) ?? ip.ToString();
            AddLog($"🚫 Blocking {ip} — matched IP rule: {matchedRule}");
            _firewallManager.BlockIp(ip);

            var entry = new BlockedEntry
            {
                IpAddress = ip,
                Hostname = null,
                MatchedDomain = $"IP: {matchedRule}",
                Timestamp = DateTime.Now
            };

            _dispatcher.Invoke(() =>
            {
                BlockedEntries.Insert(0, entry);
                BlockedCount = _firewallManager.BlockedCount;
                while (BlockedEntries.Count > 1000)
                    BlockedEntries.RemoveAt(BlockedEntries.Count - 1);
            });
            return;
        }

        // 2. Resolve rDNS and check domain-based block list
        string? hostname;
        try
        {
            hostname = await _dnsResolver.ResolveAsync(ip);
        }
        catch (Exception ex)
        {
            AddLog($"rDNS exception for {ip}: {ex.GetType().Name}: {ex.Message}");
            return;
        }

        var domains = _blockList.Domains;
        if (DnsResolver.MatchesBlockedDomain(hostname, domains))
        {
            string matchedDomain = domains.FirstOrDefault(d =>
                hostname!.EndsWith(d, StringComparison.OrdinalIgnoreCase)) ?? "unknown";

            AddLog($"🚫 Blocking {ip} ({hostname}) — matched domain {matchedDomain}");
            _firewallManager.BlockIp(ip);

            var entry = new BlockedEntry
            {
                IpAddress = ip,
                Hostname = hostname,
                MatchedDomain = matchedDomain,
                Timestamp = DateTime.Now
            };

            _dispatcher.Invoke(() =>
            {
                BlockedEntries.Insert(0, entry);
                BlockedCount = _firewallManager.BlockedCount;
                while (BlockedEntries.Count > 1000)
                    BlockedEntries.RemoveAt(BlockedEntries.Count - 1);
            });
        }
        else
        {
            AddLog($"✓ {ip} → {hostname ?? "(no rDNS)"} — not blocked");
        }
    }

    private void AddLog(string message)
    {
        var timestamped = $"[{DateTime.Now:HH:mm:ss}] {message}";
        _dispatcher.Invoke(() =>
        {
            LogEntries.Insert(0, timestamped);
            while (LogEntries.Count > 500)
                LogEntries.RemoveAt(LogEntries.Count - 1);
        });
    }

    public void Dispose()
    {
        StopProtection();
        _connectionMonitor.Dispose();
        _firewallManager.Dispose();
        _processingCts?.Dispose();
    }
}
