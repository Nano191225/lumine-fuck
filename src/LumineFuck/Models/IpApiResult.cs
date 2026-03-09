namespace LumineFuck.Models;

/// <summary>
/// Result from ip-api.com containing organisation and VPN/proxy info.
/// </summary>
public sealed class IpApiResult
{
    public string? Org { get; init; }
    /// <summary>True if ip-api.com flagged this IP as a proxy, VPN or Tor exit node.</summary>
    public bool IsProxy { get; init; }
    /// <summary>True if ip-api.com flagged this IP as belonging to a hosting/datacenter.</summary>
    public bool IsHosting { get; init; }

    /// <summary>Whether this IP is considered a VPN or datacenter (proxy OR hosting).</summary>
    public bool IsVpnLikely => IsProxy || IsHosting;

    private static readonly HashSet<string> MicrosoftKeywords = new(StringComparer.OrdinalIgnoreCase)
    {
        "microsoft", "xbox", "azure", "msn", "hotmail", "live.com"
    };

    /// <summary>
    /// Returns true when the organisation string indicates a Microsoft-owned network.
    /// Microsoft/Xbox/Azure IPs should never be treated as VPN.
    /// </summary>
    public bool IsMicrosoft =>
        Org != null && MicrosoftKeywords.Any(kw => Org.Contains(kw, StringComparison.OrdinalIgnoreCase));
}
