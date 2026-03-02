using System.Collections.Concurrent;
using System.Net;
using DnsClient;

namespace LumineFuck.Core;

/// <summary>
/// High-performance reverse DNS resolver using DnsClient.NET (PTR queries).
/// Features: parallel resolution, retry with backoff, efficient caching.
/// </summary>
public sealed class DnsResolver
{
    private readonly ConcurrentDictionary<IPAddress, DnsCacheEntry> _cache = new();
    private readonly TimeSpan _cacheTtl;
    private readonly TimeSpan _negativeCacheTtl;
    private readonly LookupClient _dnsClient;
    private readonly SemaphoreSlim _semaphore;
    private const int MaxRetries = 2;

    public record DnsCacheEntry(string? Hostname, bool Resolved, DateTime ResolvedAt);

    public event Action<string>? OnLog;

    public DnsResolver(TimeSpan? cacheTtl = null, int maxConcurrency = 16)
    {
        _cacheTtl = cacheTtl ?? TimeSpan.FromHours(1);
        _negativeCacheTtl = TimeSpan.FromMinutes(5); // Retry failed lookups sooner
        _semaphore = new SemaphoreSlim(maxConcurrency, maxConcurrency);

        // Configure DnsClient for speed and reliability
        var options = new LookupClientOptions
        {
            Timeout = TimeSpan.FromSeconds(2),
            Retries = 1,
            UseCache = true,
            CacheFailedResults = true,
            FailedResultsCacheDuration = TimeSpan.FromMinutes(1),
            UseTcpFallback = true,
            ThrowDnsErrors = false,
            ContinueOnDnsError = true,
            ContinueOnEmptyResponse = true,
        };

        _dnsClient = new LookupClient(options);
    }

    /// <summary>
    /// Resolves the reverse DNS for the given IP address using PTR query.
    /// Fast, concurrent-safe, with caching and retry.
    /// </summary>
    public async Task<string?> ResolveAsync(IPAddress ip)
    {
        // Check cache
        if (_cache.TryGetValue(ip, out var cached))
        {
            var ttl = cached.Resolved ? _cacheTtl : _negativeCacheTtl;
            if (DateTime.UtcNow - cached.ResolvedAt < ttl)
                return cached.Hostname;
            _cache.TryRemove(ip, out _);
        }

        await _semaphore.WaitAsync();
        try
        {
            // Double-check after acquiring semaphore (another thread may have resolved it)
            if (_cache.TryGetValue(ip, out cached))
            {
                var ttl = cached.Resolved ? _cacheTtl : _negativeCacheTtl;
                if (DateTime.UtcNow - cached.ResolvedAt < ttl)
                    return cached.Hostname;
                _cache.TryRemove(ip, out _);
            }

            return await ResolveWithRetryAsync(ip);
        }
        finally
        {
            _semaphore.Release();
        }
    }

    /// <summary>
    /// Resolves multiple IPs in parallel, returning results as they complete.
    /// </summary>
    public async Task<IReadOnlyList<(IPAddress Ip, string? Hostname)>> ResolveBatchAsync(
        IEnumerable<IPAddress> ips, CancellationToken ct = default)
    {
        var tasks = ips.Select(async ip =>
        {
            ct.ThrowIfCancellationRequested();
            var hostname = await ResolveAsync(ip);
            return (ip, hostname);
        });

        var results = await Task.WhenAll(tasks);
        return results;
    }

    private async Task<string?> ResolveWithRetryAsync(IPAddress ip)
    {
        for (int attempt = 0; attempt <= MaxRetries; attempt++)
        {
            try
            {
                var result = await _dnsClient.QueryReverseAsync(ip);

                if (result.HasError)
                {
                    // Check if it's a definitive "no rDNS" (NXDOMAIN, Refused) — don't retry
                    var errorMsg = result.ErrorMessage ?? "";
                    if (errorMsg.Contains("Non-Existent Domain", StringComparison.OrdinalIgnoreCase)
                        || errorMsg.Contains("NXDOMAIN", StringComparison.OrdinalIgnoreCase)
                        || errorMsg.Contains("Refused", StringComparison.OrdinalIgnoreCase)
                        || errorMsg.Contains("NotExistent", StringComparison.OrdinalIgnoreCase))
                    {
                        CacheResult(ip, null, false);
                        OnLog?.Invoke($"rDNS: {ip} → NXDOMAIN");
                        return null;
                    }

                    // Server failure — retry
                    if (attempt < MaxRetries)
                    {
                        await Task.Delay(50 * (attempt + 1));
                        continue;
                    }

                    CacheResult(ip, null, false);
                    OnLog?.Invoke($"rDNS failed: {ip} ({result.ErrorMessage})");
                    return null;
                }

                var ptrRecords = result.Answers.PtrRecords().ToList();
                if (ptrRecords.Count > 0)
                {
                    // Remove trailing dot from PTR record
                    string hostname = ptrRecords[0].PtrDomainName.Value.TrimEnd('.');
                    CacheResult(ip, hostname, true);
                    OnLog?.Invoke($"rDNS: {ip} → {hostname}");
                    return hostname;
                }

                // No PTR records found
                CacheResult(ip, null, false);
                OnLog?.Invoke($"rDNS: {ip} → (no PTR record)");
                return null;
            }
            catch (DnsResponseException) when (attempt < MaxRetries)
            {
                await Task.Delay(50 * (attempt + 1));
            }
            catch (Exception ex) when (attempt == MaxRetries)
            {
                CacheResult(ip, null, false);
                OnLog?.Invoke($"rDNS error: {ip} — {ex.GetType().Name}: {ex.Message}");
                return null;
            }
            catch (Exception) when (attempt < MaxRetries)
            {
                await Task.Delay(100 * (attempt + 1));
            }
        }

        CacheResult(ip, null, false);
        return null;
    }

    private void CacheResult(IPAddress ip, string? hostname, bool resolved)
    {
        _cache[ip] = new DnsCacheEntry(hostname, resolved, DateTime.UtcNow);
    }

    /// <summary>
    /// Checks if a hostname matches any of the blocked domain suffixes.
    /// </summary>
    public static bool MatchesBlockedDomain(string? hostname, IReadOnlyList<string> blockedDomains)
    {
        if (string.IsNullOrEmpty(hostname)) return false;

        foreach (var domain in blockedDomains)
        {
            if (hostname.EndsWith(domain, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    public void ClearCache()
    {
        _cache.Clear();
    }

    public IReadOnlyDictionary<IPAddress, DnsCacheEntry> GetCacheSnapshot()
    {
        return new Dictionary<IPAddress, DnsCacheEntry>(_cache);
    }
}
