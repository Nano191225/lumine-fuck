using System.Net;

namespace LumineFuck.Models;

/// <summary>
/// Represents a blocked connection entry in the log.
/// </summary>
public sealed class BlockedEntry
{
    public IPAddress IpAddress { get; init; } = IPAddress.None;
    public string IpAddressString => IpAddress.ToString();
    public string? Hostname { get; init; }
    public string MatchedDomain { get; init; } = string.Empty;
    public DateTime Timestamp { get; init; } = DateTime.Now;
    public string TimestampString => Timestamp.ToString("yyyy-MM-dd HH:mm:ss");
}
