namespace LumineFuck.Models;

/// <summary>
/// Represents a blocked domain suffix entry.
/// </summary>
public sealed class BlockedDomain
{
    public string Suffix { get; set; } = string.Empty;

    public override string ToString() => Suffix;
}
