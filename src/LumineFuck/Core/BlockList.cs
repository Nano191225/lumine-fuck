using System.IO;
using System.Net;
using System.Text.Json;

namespace LumineFuck.Core;

/// <summary>
/// Persisted block list containing both domain suffixes and IP addresses/CIDR ranges.
/// Stored at %AppData%\LumineFuck\blocklist.json.
/// </summary>
public sealed class BlockList
{
    private readonly string _filePath;
    private readonly string _seedFilePath;
    private List<string> _domains = new();
    private List<string> _ips = new();           // Individual IPs or CIDR notation
    private List<IpRange> _parsedRanges = new(); // Precomputed for fast matching
    private readonly object _lock = new();

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    public event Action? OnChanged;
    public event Action<string>? OnLog;

    public IReadOnlyList<string> Domains
    {
        get { lock (_lock) return _domains.AsReadOnly(); }
    }

    public IReadOnlyList<string> BlockedIps
    {
        get { lock (_lock) return _ips.AsReadOnly(); }
    }

    private int _unblockAfterSeconds = 10;
    /// <summary>
    /// Seconds after which a blocked IP is automatically unblocked. 0 = never unblock.
    /// </summary>
    public int UnblockAfterSeconds
    {
        get { lock (_lock) return _unblockAfterSeconds; }
        set
        {
            lock (_lock)
            {
                if (_unblockAfterSeconds == value) return;
                _unblockAfterSeconds = Math.Max(0, value);
                Save();
            }
            OnLog?.Invoke($"Auto-unblock after: {value}s");
            OnChanged?.Invoke();
        }
    }

    private int _blockDelaySeconds = 5;
    /// <summary>
    /// Seconds to wait after detection before actually blocking. 0 = block immediately.
    /// </summary>
    public int BlockDelaySeconds
    {
        get { lock (_lock) return _blockDelaySeconds; }
        set
        {
            lock (_lock)
            {
                if (_blockDelaySeconds == value) return;
                _blockDelaySeconds = Math.Max(0, value);
                Save();
            }
            OnLog?.Invoke($"Block delay: {value}s");
            OnChanged?.Invoke();
        }
    }

    private bool _showNotifications = true;
    /// <summary>
    /// Whether to show a desktop notification each time a connection is blocked.
    /// </summary>
    public bool ShowNotifications
    {
        get { lock (_lock) return _showNotifications; }
        set
        {
            lock (_lock)
            {
                if (_showNotifications == value) return;
                _showNotifications = value;
                Save();
            }
            OnLog?.Invoke($"Show notifications: {value}");
            OnChanged?.Invoke();
        }
    }

    private bool _blockVpn = true;
    /// <summary>
    /// When true, connections from VPN/proxy/hosting IPs (non-Microsoft) are automatically blocked.
    /// </summary>
    public bool BlockVpn
    {
        get { lock (_lock) return _blockVpn; }
        set
        {
            lock (_lock)
            {
                if (_blockVpn == value) return;
                _blockVpn = value;
                Save();
            }
            OnLog?.Invoke($"Block VPN: {value}");
            OnChanged?.Invoke();
        }
    }

    private bool _blockMsRelay = true;
    /// <summary>
    /// When true, Microsoft TURN relay IPs are automatically blocked if high-frequency traffic
    /// is detected after an attacker has been blocked.
    /// </summary>
    public bool BlockMsRelay
    {
        get { lock (_lock) return _blockMsRelay; }
        set
        {
            lock (_lock)
            {
                if (_blockMsRelay == value) return;
                _blockMsRelay = value;
                Save();
            }
            OnLog?.Invoke($"Block MS Relay: {value}");
            OnChanged?.Invoke();
        }
    }

    private int _relayWatchSeconds = 30;
    /// <summary>
    /// Seconds to watch for suspicious Microsoft relay traffic after an attacker is blocked.
    /// </summary>
    public int RelayWatchSeconds
    {
        get { lock (_lock) return _relayWatchSeconds; }
        set
        {
            lock (_lock)
            {
                if (_relayWatchSeconds == value) return;
                _relayWatchSeconds = Math.Max(1, value);
                Save();
            }
            OnLog?.Invoke($"Relay watch window: {value}s");
            OnChanged?.Invoke();
        }
    }

    private int _relayFreqThreshold = 10;
    /// <summary>
    /// Packets-per-2-seconds threshold above which a Microsoft relay IP is considered suspicious.
    /// </summary>
    public int RelayFreqThreshold
    {
        get { lock (_lock) return _relayFreqThreshold; }
        set
        {
            lock (_lock)
            {
                if (_relayFreqThreshold == value) return;
                _relayFreqThreshold = Math.Max(1, value);
                Save();
            }
            OnLog?.Invoke($"Relay freq threshold: {value} pkt/0.5s");
            OnChanged?.Invoke();
        }
    }

    public BlockList()
    {
        var appDataDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "LumineFuck");

        Directory.CreateDirectory(appDataDir);
        _filePath = Path.Combine(appDataDir, "blocklist.json");

        _seedFilePath = Path.Combine(
            AppDomain.CurrentDomain.BaseDirectory,
            "Resources", "blocked-domains.json");

        // Migrate old file if exists
        var oldFile = Path.Combine(appDataDir, "blocked-domains.json");
        if (File.Exists(oldFile) && !File.Exists(_filePath))
        {
            try
            {
                var oldJson = File.ReadAllText(oldFile);
                var oldDomains = JsonSerializer.Deserialize<List<string>>(oldJson) ?? new();
                var data = new BlockListData { Domains = oldDomains, Ips = new() };
                File.WriteAllText(_filePath, JsonSerializer.Serialize(data, JsonOptions));
                OnLog?.Invoke("Migrated old blocked-domains.json to blocklist.json.");
            }
            catch { /* ignore migration errors */ }
        }
    }

    /// <summary>
    /// Loads block list from persistent storage, or seeds from default if first run.
    /// </summary>
    public void Load()
    {
        lock (_lock)
        {
            if (File.Exists(_filePath))
            {
                try
                {
                    var json = File.ReadAllText(_filePath);
                    var data = JsonSerializer.Deserialize<BlockListData>(json);
                    if (data != null)
                    {
                        _domains = data.Domains ?? new();
                        _ips = data.Ips ?? new();
                        _unblockAfterSeconds = data.UnblockAfterSeconds;
                        _blockDelaySeconds = data.BlockDelaySeconds;
                        _showNotifications = data.ShowNotifications;
                        _blockVpn = data.BlockVpn;
                        _blockMsRelay = data.BlockMsRelay;
                        _relayWatchSeconds = data.RelayWatchSeconds > 0 ? data.RelayWatchSeconds : 30;
                        _relayFreqThreshold = data.RelayFreqThreshold > 0 ? data.RelayFreqThreshold : 10;
                        RebuildIpRanges();
                        OnLog?.Invoke($"Loaded {_domains.Count} domain(s) + {_ips.Count} IP rule(s) from config. UnblockAfter={_unblockAfterSeconds}s");
                        return;
                    }
                }
                catch (Exception ex)
                {
                    OnLog?.Invoke($"Error loading block list: {ex.Message}");
                }
            }

            // First run or error: seed from bundled defaults
            if (File.Exists(_seedFilePath))
            {
                try
                {
                    var json = File.ReadAllText(_seedFilePath);
                    // Try new format first
                    try
                    {
                        var data = JsonSerializer.Deserialize<BlockListData>(json);
                        if (data != null)
                        {
                            _domains = data.Domains ?? new();
                            _ips = data.Ips ?? new();
                            RebuildIpRanges();
                            Save();
                            OnLog?.Invoke($"Seeded {_domains.Count} domain(s) + {_ips.Count} IP rule(s).");
                            return;
                        }
                    }
                    catch { }

                    // Old format: plain string array of domains
                    var seedDomains = JsonSerializer.Deserialize<List<string>>(json) ?? new();
                    _domains = seedDomains;
                    _ips = new();
                    _parsedRanges = new();
                    Save();
                    OnLog?.Invoke($"Seeded {_domains.Count} default blocked domain(s).");
                    return;
                }
                catch (Exception ex)
                {
                    OnLog?.Invoke($"Error loading seed data: {ex.Message}");
                }
            }

            // Fallback
            _domains = new List<string> { ".orangevps.com" };
            _ips = new();
            _parsedRanges = new();
            Save();
            OnLog?.Invoke("Using hardcoded default blocked domain: .orangevps.com");
        }
    }

    // --- Domain management ---

    public void AddDomain(string domain)
    {
        if (string.IsNullOrWhiteSpace(domain)) return;

        domain = domain.Trim().ToLowerInvariant();
        if (!domain.StartsWith('.'))
            domain = "." + domain;

        lock (_lock)
        {
            if (_domains.Contains(domain)) return;
            _domains.Add(domain);
            Save();
        }

        OnLog?.Invoke($"Added blocked domain: {domain}");
        OnChanged?.Invoke();
    }

    public void RemoveDomain(string domain)
    {
        lock (_lock)
        {
            if (_domains.Remove(domain))
                Save();
        }

        OnLog?.Invoke($"Removed blocked domain: {domain}");
        OnChanged?.Invoke();
    }

    // --- IP / CIDR management ---

    /// <summary>
    /// Add an IP address or CIDR range (e.g. "1.2.3.4" or "1.2.3.0/24").
    /// </summary>
    public void AddIp(string ipOrCidr)
    {
        if (string.IsNullOrWhiteSpace(ipOrCidr)) return;
        ipOrCidr = ipOrCidr.Trim();

        lock (_lock)
        {
            if (_ips.Contains(ipOrCidr, StringComparer.OrdinalIgnoreCase)) return;
            _ips.Add(ipOrCidr);
            RebuildIpRanges();
            Save();
        }

        OnLog?.Invoke($"Added blocked IP: {ipOrCidr}");
        OnChanged?.Invoke();
    }

    public void RemoveIp(string ipOrCidr)
    {
        lock (_lock)
        {
            if (_ips.Remove(ipOrCidr))
            {
                RebuildIpRanges();
                Save();
            }
        }

        OnLog?.Invoke($"Removed blocked IP: {ipOrCidr}");
        OnChanged?.Invoke();
    }

    /// <summary>
    /// Check if an IP matches any blocked IP address or CIDR range.
    /// </summary>
    public bool MatchesBlockedIp(IPAddress ip)
    {
        lock (_lock)
        {
            foreach (var range in _parsedRanges)
            {
                if (range.Contains(ip))
                    return true;
            }
        }
        return false;
    }

    /// <summary>
    /// Get the matching IP/CIDR rule string for a given IP.
    /// </summary>
    public string? GetMatchedIpRule(IPAddress ip)
    {
        lock (_lock)
        {
            for (int i = 0; i < _parsedRanges.Count; i++)
            {
                if (_parsedRanges[i].Contains(ip))
                    return _ips[i];
            }
        }
        return null;
    }

    public void SetDomains(IEnumerable<string> domains)
    {
        lock (_lock)
        {
            _domains = domains
                .Select(d => d.Trim().ToLowerInvariant())
                .Where(d => !string.IsNullOrEmpty(d))
                .Select(d => d.StartsWith('.') ? d : "." + d)
                .Distinct()
                .ToList();
            Save();
        }

        OnChanged?.Invoke();
    }

    private void Save()
    {
        // lock held by caller
        try
        {
            var data = new BlockListData { Domains = _domains, Ips = _ips, UnblockAfterSeconds = _unblockAfterSeconds, BlockDelaySeconds = _blockDelaySeconds, ShowNotifications = _showNotifications, BlockVpn = _blockVpn, BlockMsRelay = _blockMsRelay, RelayWatchSeconds = _relayWatchSeconds, RelayFreqThreshold = _relayFreqThreshold };
            var json = JsonSerializer.Serialize(data, JsonOptions);
            File.WriteAllText(_filePath, json);
        }
        catch (Exception ex)
        {
            OnLog?.Invoke($"Error saving block list: {ex.Message}");
        }
    }

    private void RebuildIpRanges()
    {
        var ranges = new List<IpRange>();
        foreach (var entry in _ips)
        {
            try
            {
                ranges.Add(IpRange.Parse(entry));
            }
            catch (Exception ex)
            {
                OnLog?.Invoke($"Invalid IP/CIDR '{entry}': {ex.Message}");
                ranges.Add(IpRange.Empty); // placeholder to keep indices aligned
            }
        }
        _parsedRanges = ranges;
    }

    // --- Serialization model ---

    private sealed class BlockListData
    {
        public List<string> Domains { get; set; } = new();
        public List<string> Ips { get; set; } = new();
        public int UnblockAfterSeconds { get; set; } = 10;
        public int BlockDelaySeconds { get; set; } = 5;
        public bool ShowNotifications { get; set; } = true;
        public bool BlockVpn { get; set; } = true;
        public bool BlockMsRelay { get; set; } = true;
        public int RelayWatchSeconds { get; set; } = 30;
        public int RelayFreqThreshold { get; set; } = 10;
    }

    // --- IP Range helper ---

    private readonly struct IpRange
    {
        private readonly uint _network;
        private readonly uint _mask;
        private readonly bool _valid;

        public static readonly IpRange Empty = new(0, 0, false);

        private IpRange(uint network, uint mask, bool valid)
        {
            _network = network;
            _mask = mask;
            _valid = valid;
        }

        public static IpRange Parse(string ipOrCidr)
        {
            var parts = ipOrCidr.Split('/');
            if (!IPAddress.TryParse(parts[0].Trim(), out var ip))
                throw new FormatException($"Invalid IP address: {parts[0]}");

            uint addr = IpToUint(ip);

            if (parts.Length == 2 && int.TryParse(parts[1].Trim(), out int prefix))
            {
                if (prefix < 0 || prefix > 32)
                    throw new FormatException($"Invalid CIDR prefix: /{prefix}");

                uint mask = prefix == 0 ? 0 : uint.MaxValue << (32 - prefix);
                return new IpRange(addr & mask, mask, true);
            }

            // Single IP = /32
            return new IpRange(addr, uint.MaxValue, true);
        }

        public bool Contains(IPAddress ip)
        {
            if (!_valid) return false;
            uint addr = IpToUint(ip);
            return (addr & _mask) == _network;
        }

        private static uint IpToUint(IPAddress ip)
        {
            var bytes = ip.GetAddressBytes();
            return (uint)(bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3]);
        }
    }
}
