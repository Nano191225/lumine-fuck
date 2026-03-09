using System.Collections.Concurrent;
using System.Net;
using System.Net.Http;
using System.Text.Json;

namespace LumineFuck.Services;

/// <summary>
/// Looks up ISP/organisation info for an IP address via ip-api.com (free tier).
/// Results are cached per IP to minimise API calls.
/// </summary>
public sealed class IspLookupService
{
    private static readonly HttpClient _http = new()
    {
        Timeout = TimeSpan.FromSeconds(4)
    };

    private readonly ConcurrentDictionary<string, string> _cache = new();

    public async Task<string?> LookupAsync(IPAddress ip)
    {
        var ipStr = ip.ToString();

        if (_cache.TryGetValue(ipStr, out var cached))
            return cached;

        try
        {
            var json = await _http.GetStringAsync(
                $"http://ip-api.com/json/{ipStr}?fields=org");

            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.TryGetProperty("org", out var orgElem))
            {
                var org = orgElem.GetString();
                if (!string.IsNullOrEmpty(org))
                {
                    _cache[ipStr] = org;
                    return org;
                }
            }
        }
        catch
        {
            // Network unavailable or rate-limited — silently skip
        }

        return null;
    }
}
