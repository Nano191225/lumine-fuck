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
                        RebuildIpRanges();
                        OnLog?.Invoke($"Loaded {_domains.Count} domain(s) + {_ips.Count} IP rule(s) from config.");
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
            var data = new BlockListData { Domains = _domains, Ips = _ips };
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
