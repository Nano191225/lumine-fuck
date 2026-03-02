using System.Collections.Concurrent;
using System.Net;
using DnsClient;
using DnsClient.Protocol;

namespace LumineFuck.Core;

/// <summary>
/// Detects Microsoft Azure IPs by querying Team Cymru's DNS-based ASN lookup service.
/// Query: TXT &lt;reversed-ip&gt;.origin.asn.cymru.com → "8075 | 20.192.0.0/10 | US | arin | ..."
/// This catches ALL Microsoft-owned IPs including those not listed in ServiceTags_Public.
/// </summary>
public sealed class AzureIpRangeService : IDisposable
{
    private readonly LookupClient _dnsClient;
    private readonly ConcurrentDictionary<uint, AsnCacheEntry> _cache = new();
    private readonly SemaphoreSlim _semaphore;

    private static readonly TimeSpan PositiveCacheTtl = TimeSpan.FromHours(2);
    private static readonly TimeSpan NegativeCacheTtl = TimeSpan.FromMinutes(10);

    // Microsoft Corporation ASNs (source: PeeringDB / bgp.he.net)
    private static readonly HashSet<int> MicrosoftAsns = new()
    {
        8075,   // MICROSOFT-CORP-MSN-AS-BLOCK — primary Azure ASN
        8068,   // MICROSOFT-CORP-MSN-AS-BLOCK
        8069,   // MICROSOFT-CORP-MSN-AS-BLOCK
        12076,  // MICROSOFT-CORP-MSN-AS-BLOCK (ExpressRoute)
        6584,   // MICROSOFT-CORP-MSN-AS-BLOCK
        23468,  // MICROSOFT-CORP-MSN-AS-BLOCK
        35106,  // MICROSOFT-CORP-MSN-AS-BLOCK
        45139,  // MICROSOFT-CORP-MSN-AS-BLOCK
        52985,  // MICROSOFT-CORP-MSN-AS-BLOCK
        58862,  // MICROSOFT-CORP-MSN-AS-BLOCK
        59067,  // MICROSOFT-CORP-MSN-AS-BLOCK
        200017, // MICROSOFT-CORP-AS
    };

    public event Action<string>? OnLog;

    private record AsnCacheEntry(bool IsMicrosoft, DateTime ResolvedAt);

    public AzureIpRangeService(int maxConcurrency = 8)
    {
        _semaphore = new SemaphoreSlim(maxConcurrency, maxConcurrency);

        var options = new LookupClientOptions
        {
            Timeout = TimeSpan.FromSeconds(3),
            Retries = 1,
            UseCache = true,
            ThrowDnsErrors = false,
            ContinueOnDnsError = true,
            ContinueOnEmptyResponse = true,
        };

        _dnsClient = new LookupClient(options);
    }

    /// <summary>No-op for backward compat. ASN lookups are on-demand, no pre-loading needed.</summary>
    public Task InitializeAsync()
    {
        OnLog?.Invoke("Azure ASN detection enabled (Team Cymru DNS lookup).");
        return Task.CompletedTask;
    }

    /// <summary>
    /// Checks whether an IP belongs to a Microsoft ASN via Team Cymru DNS.
    /// Results are cached to avoid repeated lookups.
    /// </summary>
    public async Task<bool> IsAzureIpAsync(IPAddress ip)
    {
        if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            return false;

        uint ipUint = IpToUint(ip);

        // Check cache
        if (_cache.TryGetValue(ipUint, out var cached))
        {
            var ttl = cached.IsMicrosoft ? PositiveCacheTtl : NegativeCacheTtl;
            if (DateTime.UtcNow - cached.ResolvedAt < ttl)
                return cached.IsMicrosoft;
            _cache.TryRemove(ipUint, out _);
        }

        await _semaphore.WaitAsync();
        try
        {
            // Double-check cache after acquiring semaphore
            if (_cache.TryGetValue(ipUint, out cached))
            {
                var ttl = cached.IsMicrosoft ? PositiveCacheTtl : NegativeCacheTtl;
                if (DateTime.UtcNow - cached.ResolvedAt < ttl)
                    return cached.IsMicrosoft;
            }

            var result = await LookupAsnAsync(ip);
            _cache[ipUint] = new AsnCacheEntry(result, DateTime.UtcNow);
            return result;
        }
        finally
        {
            _semaphore.Release();
        }
    }

    /// <summary>
    /// Query Team Cymru's DNS to get the ASN for an IP, then check if it's Microsoft's.
    /// Format: dig TXT &lt;d&gt;.&lt;c&gt;.&lt;b&gt;.&lt;a&gt;.origin.asn.cymru.com
    /// Response: "8075 | 20.192.0.0/10 | US | arin | 2019-10-01"
    /// </summary>
    private async Task<bool> LookupAsnAsync(IPAddress ip)
    {
        try
        {
            var bytes = ip.GetAddressBytes();
            var queryName = $"{bytes[3]}.{bytes[2]}.{bytes[1]}.{bytes[0]}.origin.asn.cymru.com";

            var result = await _dnsClient.QueryAsync(queryName, QueryType.TXT);

            if (result.HasError)
            {
                OnLog?.Invoke($"ASN lookup error for {ip}: {result.ErrorMessage}");
                return false;
            }

            foreach (var record in result.Answers.OfType<TxtRecord>())
            {
                var txt = string.Join("", record.Text);
                // Format: "ASN | prefix | CC | registry | date"
                var pipeIdx = txt.IndexOf('|');
                if (pipeIdx <= 0) continue;

                var asnStr = txt[..pipeIdx].Trim();

                // Could be multiple ASNs separated by space (multi-origin)
                foreach (var part in asnStr.Split(' ', StringSplitOptions.RemoveEmptyEntries))
                {
                    if (int.TryParse(part, out int asn) && MicrosoftAsns.Contains(asn))
                    {
                        OnLog?.Invoke($"ASN lookup: {ip} → AS{asn} (Microsoft)");
                        return true;
                    }
                }
            }

            return false;
        }
        catch (Exception ex)
        {
            OnLog?.Invoke($"ASN lookup exception for {ip}: {ex.Message}");
            return false;
        }
    }

    private static uint IpToUint(IPAddress ip)
    {
        var bytes = ip.GetAddressBytes();
        return (uint)(bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3]);
    }

    public void Dispose()
    {
        _semaphore.Dispose();
    }
}
