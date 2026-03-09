using System.Net;

namespace LumineFuck.Models;

/// <summary>
/// Represents a detected network connection entry in the Connection Log.
/// </summary>
public sealed class ConnectionLogEntry
{
    public DateTime Timestamp { get; init; } = DateTime.Now;
    public IPAddress IpAddress { get; init; } = IPAddress.None;
    public string? Rdns { get; init; }
    public string? Isp { get; init; }

    public string TimestampString => Timestamp.ToString("yyyy-MM-dd HH:mm:ss");
    public string IpAddressString => IpAddress.ToString();
    public string RdnsDisplay => Rdns ?? "—";
    public string IspDisplay => Isp ?? "—";
}
