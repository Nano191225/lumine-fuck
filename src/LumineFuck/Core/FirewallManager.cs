using System.Net;
using System.Net.Sockets;
using System.Windows.Threading;

namespace LumineFuck.Core;

/// <summary>
/// Manages Windows Firewall block rules via dynamic COM (HNetCfg.FwPolicy2).
/// Creates 4 rules per block set: TCP In, TCP Out, UDP In, UDP Out.
/// All COM operations are dispatched to the STA UI thread to avoid apartment violations.
/// </summary>
public sealed class FirewallManager : IDisposable
{
    private const string RulePrefix = "LumineFW_Block";
    private const string RuleGroupName = "LumineFuck Firewall";

    // Rule name suffixes
    private const string RuleTcpIn = RulePrefix + "_TCP_IN";
    private const string RuleTcpOut = RulePrefix + "_TCP_OUT";
    private const string RuleUdpIn = RulePrefix + "_UDP_IN";
    private const string RuleUdpOut = RulePrefix + "_UDP_OUT";

    // COM constants
    private const int NET_FW_ACTION_BLOCK = 0;
    private const int NET_FW_RULE_DIR_IN = 1;
    private const int NET_FW_RULE_DIR_OUT = 2;
    private const int NET_FW_IP_PROTOCOL_TCP = 6;
    private const int NET_FW_IP_PROTOCOL_UDP = 17;

    private dynamic? _policy;
    private readonly HashSet<string> _blockedIps = new();
    private readonly object _lock = new();
    private readonly Dispatcher _dispatcher;

    public event Action<string>? OnLog;

    public int BlockedCount
    {
        get { lock (_lock) return _blockedIps.Count; }
    }

    public bool IsBlocked(IPAddress ip)
    {
        lock (_lock) return _blockedIps.Contains(ip.ToString());
    }

    public FirewallManager(Dispatcher dispatcher)
    {
        _dispatcher = dispatcher;
        _dispatcher.Invoke(InitializePolicy);
    }

    private void InitializePolicy()
    {
        try
        {
            var policyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2")
                ?? throw new InvalidOperationException("Cannot access Windows Firewall COM interface.");
            _policy = Activator.CreateInstance(policyType)
                ?? throw new InvalidOperationException("Failed to create FwPolicy2 instance.");
            LoadExistingRules();
        }
        catch (Exception ex)
        {
            OnLog?.Invoke($"Firewall init error: {ex.Message}");
        }
    }

    /// <summary>
    /// Adds an IP address to all firewall block rules (TCP/UDP, In/Out).
    /// </summary>
    public bool BlockIp(IPAddress ip)
    {
        string ipStr = ip.ToString();
        bool added;

        lock (_lock)
            added = _blockedIps.Add(ipStr);

        if (!added) return false;

        _dispatcher.Invoke(() =>
        {
            lock (_lock) UpdateAllFirewallRules();
        });

        OnLog?.Invoke($"🚫 Blocked IP: {ipStr}");
        return true;
    }

    /// <summary>
    /// Removes all LumineFW block rules from Windows Firewall.
    /// </summary>
    public void UnblockAll()
    {
        lock (_lock) _blockedIps.Clear();

        _dispatcher.Invoke(() =>
        {
            try
            {
                if (_policy == null) return;
                var rules = _policy.Rules;
                var toRemove = new List<string>();

                foreach (dynamic rule in rules)
                {
                    string? name = rule.Name;
                    if (name?.StartsWith(RulePrefix) == true)
                        toRemove.Add(name);
                }

                foreach (var name in toRemove)
                    rules.Remove(name);

                OnLog?.Invoke($"Removed {toRemove.Count} firewall rule(s).");
            }
            catch (Exception ex)
            {
                OnLog?.Invoke($"Error removing rules: {ex.Message}");
            }
        });
    }

    /// <summary>
    /// Removes a single IP from all firewall block rules.
    /// </summary>
    public bool UnblockIp(IPAddress ip)
    {
        string ipStr = ip.ToString();
        bool removed;

        lock (_lock)
            removed = _blockedIps.Remove(ipStr);

        if (!removed) return false;

        _dispatcher.Invoke(() =>
        {
            lock (_lock) UpdateAllFirewallRules();
        });

        OnLog?.Invoke($"✅ Unblocked IP: {ipStr}");
        return true;
    }

    public List<string> GetBlockedIps()
    {
        lock (_lock)
            return [.. _blockedIps];
    }

    private void UpdateAllFirewallRules()
    {
        // Must be called from the STA dispatcher thread.
        if (_policy == null) return;

        if (_blockedIps.Count == 0)
        {
            RemoveAllRules();
            return;
        }

        string remoteAddresses = string.Join(",", _blockedIps.Select(ip => $"{ip}/255.255.255.255"));

        // Create/update 4 rules: TCP In, TCP Out, UDP In, UDP Out
        UpdateOrCreateRule(RuleTcpIn, NET_FW_IP_PROTOCOL_TCP, NET_FW_RULE_DIR_IN, remoteAddresses);
        UpdateOrCreateRule(RuleTcpOut, NET_FW_IP_PROTOCOL_TCP, NET_FW_RULE_DIR_OUT, remoteAddresses);
        UpdateOrCreateRule(RuleUdpIn, NET_FW_IP_PROTOCOL_UDP, NET_FW_RULE_DIR_IN, remoteAddresses);
        UpdateOrCreateRule(RuleUdpOut, NET_FW_IP_PROTOCOL_UDP, NET_FW_RULE_DIR_OUT, remoteAddresses);
    }

    private void UpdateOrCreateRule(string ruleName, int protocol, int direction, string remoteAddresses)
    {
        if (_policy == null) return;
        try
        {
            var rules = _policy.Rules;
            dynamic? existingRule = null;

            try
            {
                existingRule = rules.Item(ruleName);
            }
            catch { /* Rule doesn't exist yet */ }

            if (existingRule != null)
            {
                existingRule.RemoteAddresses = remoteAddresses;
                existingRule.Enabled = true;
            }
            else
            {
                var ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule")
                    ?? throw new InvalidOperationException("Cannot create firewall rule COM object.");
                dynamic rule = Activator.CreateInstance(ruleType)
                    ?? throw new InvalidOperationException("Failed to create FWRule instance.");

                string protoName = protocol == NET_FW_IP_PROTOCOL_TCP ? "TCP" : "UDP";
                string dirName = direction == NET_FW_RULE_DIR_IN ? "Inbound" : "Outbound";

                rule.Name = ruleName;
                rule.Description = $"Auto-generated by LumineFuck Firewall — {protoName} {dirName} block for rDNS-matched IPs.";
                rule.Grouping = RuleGroupName;
                rule.Action = NET_FW_ACTION_BLOCK;
                rule.Direction = direction;
                rule.Protocol = protocol;
                rule.RemoteAddresses = remoteAddresses;
                rule.Profiles = 7; // Domain (1) | Private (2) | Public (4) = all profiles
                rule.Enabled = true;

                rules.Add(rule);
                OnLog?.Invoke($"Created firewall rule: {ruleName}");
            }
        }
        catch (Exception ex)
        {
            OnLog?.Invoke($"Firewall rule error ({ruleName}): {ex.Message}");
        }
    }

    private void RemoveAllRules()
    {
        if (_policy == null) return;
        string[] ruleNames = [RuleTcpIn, RuleTcpOut, RuleUdpIn, RuleUdpOut];
        foreach (var name in ruleNames)
        {
            try { _policy.Rules.Remove(name); } catch { }
        }
    }

    private void LoadExistingRules()
    {
        // Must be called from the STA dispatcher thread.
        if (_policy == null) return;
        try
        {
            foreach (dynamic rule in _policy.Rules)
            {
                string? name = rule.Name;
                if (name?.StartsWith(RulePrefix) != true) continue;

                string? addrs = rule.RemoteAddresses;
                if (string.IsNullOrEmpty(addrs)) continue;

                foreach (var addr in addrs.Split(','))
                {
                    var ip = addr.Split('/')[0].Trim();
                    if (!string.IsNullOrEmpty(ip))
                        _blockedIps.Add(ip);
                }
            }

            if (_blockedIps.Count > 0)
                OnLog?.Invoke($"Loaded {_blockedIps.Count} existing blocked IP(s) from firewall rules.");
        }
        catch (Exception ex)
        {
            OnLog?.Invoke($"Error loading existing rules: {ex.Message}");
        }
    }

    public void Dispose()
    {
        // COM objects are released by GC
    }

    /// <summary>
    /// Runs a self-test to verify the firewall integration is functioning.
    /// Step 1: Confirms the COM interface is available.
    /// Step 2: Confirms Windows Firewall is enabled on the Private profile.
    /// Step 3: Creates a temporary block rule, verifies it exists, then removes it.
    /// Step 4 (best-effort): If 1.1.1.1:80 is reachable without a rule, confirms
    ///         it becomes unreachable after a temporary block rule is added.
    /// </summary>
    public async Task<(bool Ok, List<string> Lines)> RunFirewallTestAsync()
    {
        const string testIp = "1.1.1.1";
        const int testPort = 80;
        const string testRuleName = "LumineFW_SelfTest";

        var lines = new List<string>();
        bool ok = true;

        // 1. COM interface
        if (_policy == null)
            return (false, new List<string> { "❌ Firewall COM interface is not available. Run LumineFuck as administrator." });
        lines.Add("✓ Firewall COM interface: available");

        // 2. Windows Firewall enabled on Private profile?
        bool fwEnabled = false;
        await _dispatcher.InvokeAsync(() =>
        {
            try { fwEnabled = (bool)_policy.FirewallEnabled[2]; } catch { }
        });
        if (!fwEnabled)
        {
            lines.Add("❌ Windows Firewall is DISABLED on the Private profile — enable it in Windows Security.");
            ok = false;
        }
        else
        {
            lines.Add("✓ Windows Firewall: enabled (Private profile)");
        }

        // 3. Create a temporary test rule and verify it
        bool ruleVerified = false;
        await _dispatcher.InvokeAsync(() =>
        {
            try
            {
                var ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule");
                if (ruleType == null) return;
                dynamic rule = Activator.CreateInstance(ruleType)!;
                rule.Name = testRuleName;
                rule.Description = "LumineFuck self-test — temporary, will be removed";
                rule.Grouping = RuleGroupName;
                rule.Action = NET_FW_ACTION_BLOCK;
                rule.Direction = NET_FW_RULE_DIR_OUT;
                rule.Protocol = NET_FW_IP_PROTOCOL_TCP;
                rule.RemoteAddresses = $"{testIp}/255.255.255.255";
                rule.Profiles = 7;
                rule.Enabled = true;
                _policy.Rules.Add(rule);

                // Verify it was persisted
                dynamic? found = null;
                try { found = _policy.Rules.Item(testRuleName); } catch { }
                ruleVerified = (found != null && (bool)found.Enabled);
            }
            catch { ruleVerified = false; }
            finally
            {
                try { _policy.Rules.Remove(testRuleName); } catch { }
            }
        });

        if (!ruleVerified)
        {
            lines.Add("❌ Failed to create or verify a test firewall rule — check administrator privileges.");
            ok = false;
        }
        else
        {
            lines.Add("✓ Firewall rule creation/verification: OK");
        }

        // 4. Best-effort connectivity block test
        bool baselineReachable = await TryConnectAsync(testIp, testPort, msTimeout: 1500);
        if (!baselineReachable)
        {
            lines.Add($"⚠ {testIp}:{testPort} is not reachable (no internet?) — skipping live block test.");
        }
        else
        {
            lines.Add($"✓ Baseline: {testIp}:{testPort} is reachable without a block rule");

            // Add block rule
            await _dispatcher.InvokeAsync(() =>
            {
                try
                {
                    var ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule");
                    if (ruleType == null) return;
                    dynamic rule = Activator.CreateInstance(ruleType)!;
                    rule.Name = testRuleName;
                    rule.Grouping = RuleGroupName;
                    rule.Action = NET_FW_ACTION_BLOCK;
                    rule.Direction = NET_FW_RULE_DIR_OUT;
                    rule.Protocol = NET_FW_IP_PROTOCOL_TCP;
                    rule.RemoteAddresses = $"{testIp}/255.255.255.255";
                    rule.Profiles = 7;
                    rule.Enabled = true;
                    _policy.Rules.Add(rule);
                }
                catch { }
            });

            await Task.Delay(300);

            // Connection should now fail/timeout
            bool stillReachable = await TryConnectAsync(testIp, testPort, msTimeout: 2000);

            // Remove rule
            await _dispatcher.InvokeAsync(() => { try { _policy.Rules.Remove(testRuleName); } catch { } });

            if (!stillReachable)
                lines.Add($"✓ Live block test: {testIp} was blocked by the test rule ✅");
            else
            {
                lines.Add($"❌ Live block test: {testIp} was NOT blocked — Windows Firewall may not be functioning correctly.");
                ok = false;
            }
        }

        return (ok, lines);
    }

    private static async Task<bool> TryConnectAsync(string host, int port, int msTimeout)
    {
        using var cts = new CancellationTokenSource(msTimeout);
        try
        {
            using var tcp = new TcpClient();
            await tcp.ConnectAsync(IPAddress.Parse(host), port, cts.Token);
            return true;
        }
        catch
        {
            return false;
        }
    }
}
