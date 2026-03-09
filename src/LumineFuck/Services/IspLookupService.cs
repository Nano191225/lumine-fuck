using System.Collections.Concurrent;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using LumineFuck.Models;

namespace LumineFuck.Services;

/// <summary>
/// Looks up ISP/organisation, proxy and hosting flags for an IP via ip-api.com (free tier).
/// Results are cached per IP to minimise API calls (45 req/min limit on free tier).
/// </summary>
public sealed class IspLookupService
{
    private static readonly HttpClient _http = new()
    {
        Timeout = TimeSpan.FromSeconds(4)
    };

    private readonly ConcurrentDictionary<string, IpApiResult> _cache = new();

    public async Task<IpApiResult?> LookupAsync(IPAddress ip)
    {
        var ipStr = ip.ToString();

        if (_cache.TryGetValue(ipStr, out var cached))
            return cached;

        try
        {
            // org, proxy, hosting are all available on the free HTTP tier
            var json = await _http.GetStringAsync(
                $"http://ip-api.com/json/{ipStr}?fields=org,proxy,hosting");

            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            var result = new IpApiResult
            {
                Org = root.TryGetProperty("org", out var orgEl) ? orgEl.GetString() : null,
                IsProxy = root.TryGetProperty("proxy", out var proxyEl) && proxyEl.GetBoolean(),
                IsHosting = root.TryGetProperty("hosting", out var hostingEl) && hostingEl.GetBoolean(),
            };

            _cache[ipStr] = result;
            return result;
        }
        catch
        {
            // Network unavailable or rate-limited — silently skip
            return null;
        }
    }
}

