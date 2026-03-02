using System.Collections.ObjectModel;
using System.Net;
using System.Windows;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using LumineFuck.Core;
using LumineFuck.Models;
using LumineFuck.Services;
using Microsoft.Toolkit.Uwp.Notifications;

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
    private readonly System.Timers.Timer _unblockTimer;
    private System.Windows.Forms.NotifyIcon? _notifyIcon;

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

        // System tray notification icon
        try
        {
            var iconPath = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Resources", "app.ico");
            _notifyIcon = new System.Windows.Forms.NotifyIcon
            {
                Icon = System.IO.File.Exists(iconPath)
                    ? new System.Drawing.Icon(iconPath)
                    : System.Drawing.SystemIcons.Shield,
                Visible = true,
                Text = "LumineFuck Firewall"
            };
        }
        catch { _notifyIcon = null; }

        // Timer to process scheduled unblocks (runs every second)
        _unblockTimer = new System.Timers.Timer(1000);
        _unblockTimer.Elapsed += UnblockTimer_Elapsed;
        _unblockTimer.AutoReset = true;

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
        ClearUnblockQueue();
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
        _processingTask = Task.Run(() => ProcessNewIpsAsync(_processingCts.Token));        _unblockTimer.Start();
        StatusText = "Active — Monitoring";
        StatusColor = "#51CF66"; // Green
        AddLog("Protection enabled.");
    }

    private void StopProtection()
    {
        _connectionMonitor.Stop();
        _processingCts?.Cancel();
        _processingTask = null;
        _unblockTimer.Stop();

        // Clear all firewall rules on stop
        _firewallManager.UnblockAll();
        _connectionMonitor.ClearCache();
        _dnsResolver.ClearCache();
        ClearUnblockQueue();
        BlockedCount = 0;
        ScannedCount = 0;
        _dispatcher.Invoke(() => BlockedEntries.Clear());

        StatusText = "Stopped";
        StatusColor = "#FF6B6B"; // Red
        AddLog("Protection disabled. All rules cleared.");
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
            BlockAndRecord(ip, null, $"IP: {matchedRule}");
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
            BlockAndRecord(ip, hostname, matchedDomain);
        }
        else
        {
            AddLog($"✓ {ip} → {hostname ?? "(no rDNS)"} — not blocked");
        }
    }

    // --- Auto-unblock queue ---

    private readonly record struct ScheduledUnblock(IPAddress Ip, DateTime UnblockAt);
    private readonly List<ScheduledUnblock> _unblockQueue = new();
    private readonly object _unblockLock = new();

    private void ScheduleUnblock(IPAddress ip)
    {
        int seconds = _blockList.UnblockAfterSeconds;
        if (seconds <= 0) return;

        lock (_unblockLock)
        {
            _unblockQueue.Add(new ScheduledUnblock(ip, DateTime.UtcNow.AddSeconds(seconds)));
        }
    }

    private void ClearUnblockQueue()
    {
        lock (_unblockLock) _unblockQueue.Clear();
    }

    private void UnblockTimer_Elapsed(object? sender, System.Timers.ElapsedEventArgs e)
    {
        List<ScheduledUnblock> due;
        lock (_unblockLock)
        {
            var now = DateTime.UtcNow;
            due = _unblockQueue.Where(u => now >= u.UnblockAt).ToList();
            foreach (var item in due)
                _unblockQueue.Remove(item);
        }

        foreach (var item in due)
        {
            _firewallManager.UnblockIp(item.Ip);
            _connectionMonitor.RemoveFromCache(item.Ip);
            _dnsResolver.RemoveFromCache(item.Ip);
            AddLog($"\u2705 Auto-unblocked {item.Ip}");
            _dispatcher.Invoke(() =>
            {
                BlockedCount = _firewallManager.BlockedCount;
                // Remove matching entries from blocked connections list
                var ipStr = item.Ip.ToString();
                for (int i = BlockedEntries.Count - 1; i >= 0; i--)
                {
                    if (BlockedEntries[i].IpAddressString == ipStr)
                        BlockedEntries.RemoveAt(i);
                }
            });
        }
    }

    // --- Helpers ---

    private async void BlockAndRecord(IPAddress ip, string? hostname, string matchedRule)
    {
        // Delay before blocking if configured
        int delaySeconds = _blockList.BlockDelaySeconds;
        if (delaySeconds > 0)
        {
            AddLog($"\u23f3 Delaying block of {ip} for {delaySeconds}s...");
            await Task.Delay(TimeSpan.FromSeconds(delaySeconds));
        }

        _firewallManager.BlockIp(ip);
        ScheduleUnblock(ip);

        if (_blockList.ShowNotifications)
        {
            try
            {
                var detail = hostname != null
                    ? $"{ip} ({hostname})"
                    : $"{ip} [{matchedRule}]";
                new ToastContentBuilder()
                    .AddText("LumineFuck \u2014 Blocked")
                    .AddText(detail)
                    .Show();
            }
            catch { /* suppress if notifications unavailable */ }
        }

        var entry = new BlockedEntry
        {
            IpAddress = ip,
            Hostname = hostname,
            MatchedDomain = matchedRule,
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
        _unblockTimer.Dispose();
        _processingCts?.Dispose();
        _notifyIcon?.Dispose();
    }
}
