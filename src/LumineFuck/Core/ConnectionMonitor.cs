using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Threading.Channels;
using PacketDotNet;
using SharpPcap;

namespace LumineFuck.Core;

/// <summary>
/// Monitors network connections from Minecraft processes only:
/// 1. TCP table polling (GetExtendedTcpTable) — PID-based process filter
/// 2. SharpPcap/Npcap UDP capture — cross-referenced with GetExtendedUdpTable for PID
/// Only traffic from Minecraft.Windows.exe or Minecraft.exe is detected.
/// </summary>
public sealed class ConnectionMonitor : IDisposable
{
    // --- P/Invoke for GetExtendedTcpTable / GetExtendedUdpTable ---
    private const int AF_INET = 2;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;
    private const int UDP_TABLE_OWNER_PID = 1;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable, ref int dwOutBufLen, bool sort,
        int ipVersion, int tblClass, uint reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(
        IntPtr pUdpTable, ref int dwOutBufLen, bool sort,
        int ipVersion, int tblClass, uint reserved);

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint dwState;
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwRemoteAddr;
        public uint dwRemotePort;
        public uint dwOwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_UDPROW_OWNER_PID
    {
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwOwningPid;
    }

    private const uint MIB_TCP_STATE_ESTAB = 5;
    private const uint MIB_TCP_STATE_SYN_RCVD = 3;
    private const uint MIB_TCP_STATE_SYN_SENT = 2;

    // Target process names (case-insensitive, without .exe)
    private static readonly HashSet<string> TargetProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "Minecraft.Windows",
        "Minecraft",
        "javaw",   // Java Edition via launcher
        "java",    // Java Edition
    };

    // --- Fields ---
    private readonly ConcurrentDictionary<string, byte> _seenIps = new();
    private readonly Channel<(IPAddress, ushort)> _newIpChannel;
    private CancellationTokenSource? _cts;
    private Task? _tcpPollingTask;
    private Task? _udpTableRefreshTask;
    private readonly List<ILiveDevice> _captureDevices = new();
    private readonly TimeSpan _pollInterval;
    private readonly HashSet<string> _localAddresses = new();

    // PID caches
    private readonly ConcurrentDictionary<uint, bool> _pidIsMinecraft = new();
    private ConcurrentDictionary<ushort, uint> _udpPortToPid = new();

    private int _tcpDetected;
    private int _udpDetected;

    // --- Post-block MS relay watch ---
    // Activated after a non-Microsoft IP is blocked.
    // If any IP sends high-frequency traffic during the watch window, it is
    // reported via OnSuspiciousRelayDetected for the caller to evaluate and block.
    private volatile bool _postBlockWatchActive = false;
    private DateTime _postBlockWatchExpiry;
    private int _currentRelayFreqThreshold = 10; // configurable via NotifyAttackerBlocked
    private const long RelayWindowMs = 500;
    private readonly ConcurrentDictionary<string, RelayCounter> _relayCounters = new();

    private sealed class RelayCounter
    {
        public int Count;
        public long WindowStartTick = Environment.TickCount64;
        // 1 = already reported this window, 0 = not yet
        public int Reported;
    }

    /// <summary>Fired when a high-frequency relay IP is detected during post-block watch.</summary>
    public event Action<IPAddress>? OnSuspiciousRelayDetected;

    /// <summary>
    /// Call this whenever a non-Microsoft attacker IP is blocked.
    /// Activates a watch window during which high-frequency IPs are reported.
    /// </summary>
    public void NotifyAttackerBlocked(int watchSeconds = 30, int freqThreshold = 10)
    {
        _currentRelayFreqThreshold = Math.Max(1, freqThreshold);
        _postBlockWatchExpiry = DateTime.UtcNow.AddSeconds(Math.Max(1, watchSeconds));
        _postBlockWatchActive = true;
        _relayCounters.Clear();
    }

    public ChannelReader<(IPAddress, ushort)> NewIpReader => _newIpChannel.Reader;

    public bool IsRunning => _tcpPollingTask is not null && !_tcpPollingTask.IsCompleted;

    public event Action<string>? OnLog;

    public ConnectionMonitor(TimeSpan? pollInterval = null)
    {
        _pollInterval = pollInterval ?? TimeSpan.FromSeconds(1);
        _newIpChannel = Channel.CreateUnbounded<(IPAddress, ushort)>(new UnboundedChannelOptions
        {
            SingleReader = false,
            SingleWriter = false  // Multiple writers: TCP poll thread + Npcap capture threads
        });

        CollectLocalAddresses();
    }

    private void CollectLocalAddresses()
    {
        _localAddresses.Add("0.0.0.0");
        _localAddresses.Add("127.0.0.1");
        _localAddresses.Add("255.255.255.255");

        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                foreach (var addr in ni.GetIPProperties().UnicastAddresses)
                {
                    if (addr.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        _localAddresses.Add(addr.Address.ToString());
                }
            }
        }
        catch { /* best effort */ }
    }

    public void Start()
    {
        if (IsRunning) return;
        _cts = new CancellationTokenSource();
        _tcpDetected = 0;
        _udpDetected = 0;
        _pidIsMinecraft.Clear();

        // Initial UDP table snapshot
        RefreshUdpPortTable();

        // Start TCP polling
        _tcpPollingTask = Task.Run(() => TcpPollLoop(_cts.Token));

        // Start periodic UDP table refresh (for port→PID mapping)
        _udpTableRefreshTask = Task.Run(() => UdpTableRefreshLoop(_cts.Token));

        // Start UDP packet capture via Npcap (SharpPcap)
        StartPacketCapture();

        OnLog?.Invoke("Connection monitor started (Minecraft process filter active).");
        OnLog?.Invoke($"  Target processes: {string.Join(", ", TargetProcessNames)}");
    }

    public void Stop()
    {
        StopPacketCapture();
        _cts?.Cancel();
        _tcpPollingTask = null;
        _udpTableRefreshTask = null;
        OnLog?.Invoke($"Connection monitor stopped. Detected: {_tcpDetected} TCP, {_udpDetected} UDP unique IPs.");
    }

    public void ClearCache()
    {
        _seenIps.Clear();
        _pidIsMinecraft.Clear();
    }

    /// <summary>
    /// Removes a single IP from the seen cache so it can be re-detected.
    /// </summary>
    public void RemoveFromCache(IPAddress ip)
    {
        _seenIps.TryRemove(ip.ToString(), out _);
    }

    // ===== Process Identification =====

    /// <summary>
    /// Check if a PID belongs to a Minecraft process. Result is cached.
    /// </summary>
    private bool IsMinecraftProcess(uint pid)
    {
        if (pid == 0) return false;

        return _pidIsMinecraft.GetOrAdd(pid, p =>
        {
            try
            {
                var proc = Process.GetProcessById((int)p);
                var name = proc.ProcessName; // without .exe
                bool isTarget = TargetProcessNames.Contains(name);
                if (isTarget)
                    OnLog?.Invoke($"  Minecraft process found: {name}.exe (PID {p})");
                return isTarget;
            }
            catch
            {
                return false; // Process already exited
            }
        });
    }

    // ===== UDP Port → PID Table =====

    private async Task UdpTableRefreshLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try { await Task.Delay(TimeSpan.FromMilliseconds(500), ct); }
            catch (TaskCanceledException) { break; }

            try
            {
                RefreshUdpPortTable();
            }
            catch (Exception ex)
            {
                OnLog?.Invoke($"UDP table refresh error: {ex.Message}");
            }
        }
    }

    private void RefreshUdpPortTable()
    {
        var newMap = new ConcurrentDictionary<ushort, uint>();

        int bufferSize = 0;
        GetExtendedUdpTable(IntPtr.Zero, ref bufferSize, true, AF_INET, UDP_TABLE_OWNER_PID, 0);

        IntPtr tablePtr = Marshal.AllocHGlobal(bufferSize);
        try
        {
            uint result = GetExtendedUdpTable(tablePtr, ref bufferSize, true, AF_INET, UDP_TABLE_OWNER_PID, 0);
            if (result != 0) return;

            int rowCount = Marshal.ReadInt32(tablePtr);
            IntPtr rowPtr = tablePtr + 4;
            int rowSize = Marshal.SizeOf<MIB_UDPROW_OWNER_PID>();

            for (int i = 0; i < rowCount; i++)
            {
                var row = Marshal.PtrToStructure<MIB_UDPROW_OWNER_PID>(rowPtr);
                rowPtr += rowSize;

                // Port is in network byte order
                ushort localPort = (ushort)IPAddress.NetworkToHostOrder((short)row.dwLocalPort);
                newMap[localPort] = row.dwOwningPid;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(tablePtr);
        }

        _udpPortToPid = newMap;
    }

    // ===== Npcap/SharpPcap UDP Capture =====

    private void StartPacketCapture()
    {
        try
        {
            var devices = CaptureDeviceList.Instance;
            if (devices.Count == 0)
            {
                OnLog?.Invoke("⚠ No capture devices found. Is Npcap installed? (https://npcap.com)");
                return;
            }

            OnLog?.Invoke($"Found {devices.Count} capture device(s).");

            foreach (var device in devices)
            {
                try
                {
                    device.OnPacketArrival += OnPacketArrival;
                    device.Open(DeviceModes.Promiscuous, 100); // 100ms read timeout

                    // Capture only UDP packets (BPF filter, same syntax as Wireshark)
                    device.Filter = "udp";

                    device.StartCapture();
                    _captureDevices.Add(device);

                    OnLog?.Invoke($"  ✓ Capturing UDP on: {device.Description ?? device.Name}");
                }
                catch (Exception ex)
                {
                    OnLog?.Invoke($"  ✗ Failed to open {device.Description ?? device.Name}: {ex.Message}");
                }
            }

            if (_captureDevices.Count == 0)
            {
                OnLog?.Invoke("⚠ Could not open any capture device. Ensure Npcap is installed with WinPcap compatibility.");
            }
        }
        catch (Exception ex)
        {
            OnLog?.Invoke($"⚠ Packet capture init failed: {ex.Message}. Is Npcap installed?");
        }
    }

    private void StopPacketCapture()
    {
        foreach (var device in _captureDevices)
        {
            try
            {
                device.StopCapture();
                device.Close();
            }
            catch { /* ignore cleanup errors */ }
        }
        _captureDevices.Clear();
    }

    private void OnPacketArrival(object sender, PacketCapture e)
    {
        try
        {
            var rawPacket = e.GetPacket();
            var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);

            var ipPacket = packet.Extract<IPv4Packet>();
            if (ipPacket == null) return;

            var udpPacket = ipPacket.Extract<UdpPacket>();
            if (udpPacket == null) return;

            var srcIp = ipPacket.SourceAddress;
            var dstIp = ipPacket.DestinationAddress;
            var srcStr = srcIp.ToString();
            var dstStr = dstIp.ToString();

            IPAddress remoteIp;
            ushort localPort;

            bool srcIsLocal = _localAddresses.Contains(srcStr) || IPAddress.IsLoopback(srcIp);
            bool dstIsLocal = _localAddresses.Contains(dstStr) || IPAddress.IsLoopback(dstIp);

            if (srcIsLocal && !dstIsLocal)
            {
                // Outgoing packet: local → remote
                remoteIp = dstIp;
                localPort = udpPacket.SourcePort; // our local port
            }
            else if (!srcIsLocal && dstIsLocal)
            {
                // Incoming packet: remote → local
                remoteIp = srcIp;
                localPort = udpPacket.DestinationPort; // our local port
            }
            else
            {
                return; // Both local or both remote — skip
            }

            // Skip multicast/broadcast
            var bytes = remoteIp.GetAddressBytes();
            if (bytes[0] >= 224) return;

            // Check if local port belongs to a Minecraft process
            if (!_udpPortToPid.TryGetValue(localPort, out var pid) || !IsMinecraftProcess(pid))
                return;

            // [DEBUG] Log every packet with a known local port (Minecraft traffic)
            bool isOutgoing = srcIsLocal;
            string direction = isOutgoing ? "OUT" : "IN ";
            ushort remotePort = isOutgoing ? udpPacket.DestinationPort : udpPacket.SourcePort;
            int payloadLen = udpPacket.PayloadData?.Length ?? 0;

            // Parse STUN packets for ICE/TURN credentials (plaintext before DTLS)
            if (payloadLen >= 20 && udpPacket.PayloadData != null)
                TryLogStunAttributes(udpPacket.PayloadData, remoteIp, remotePort, direction);

            // Post-block relay watch: detect high-frequency traffic from any IP
            if (_postBlockWatchActive)
            {
                if (DateTime.UtcNow > _postBlockWatchExpiry)
                {
                    _postBlockWatchActive = false;
                }
                else
                {
                    CheckRelayFrequency(remoteIp);
                }
            }

            var remoteStr = remoteIp.ToString();
            if (_seenIps.TryAdd(remoteStr, 0))
            {
                _newIpChannel.Writer.TryWrite((remoteIp, localPort));
                Interlocked.Increment(ref _udpDetected);
                OnLog?.Invoke($"[UDP/MC] New IP: {remoteIp} (local port: {localPort}, PID: {pid})");
            }
        }
        catch
        {
            // Malformed packet — ignore
        }
    }

    // ===== TCP Polling via GetExtendedTcpTable =====

    private async Task TcpPollLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                ScanTcpTable();
            }
            catch (Exception ex)
            {
                OnLog?.Invoke($"TCP scan error: {ex.Message}");
            }

            try { await Task.Delay(_pollInterval, ct); }
            catch (TaskCanceledException) { break; }
        }
    }

    private void ScanTcpTable()
    {
        int bufferSize = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

        IntPtr tcpTablePtr = Marshal.AllocHGlobal(bufferSize);
        try
        {
            uint result = GetExtendedTcpTable(tcpTablePtr, ref bufferSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            if (result != 0) return;

            int rowCount = Marshal.ReadInt32(tcpTablePtr);
            IntPtr rowPtr = tcpTablePtr + 4;
            int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

            for (int i = 0; i < rowCount; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                rowPtr += rowSize;

                if (row.dwState != MIB_TCP_STATE_ESTAB &&
                    row.dwState != MIB_TCP_STATE_SYN_RCVD &&
                    row.dwState != MIB_TCP_STATE_SYN_SENT)
                    continue;

                uint remoteAddr = row.dwRemoteAddr;
                if (remoteAddr == 0 || remoteAddr == 0x0100007F)
                    continue;

                // Filter: only Minecraft processes
                if (!IsMinecraftProcess(row.dwOwningPid))
                    continue;

                var ip = new IPAddress(remoteAddr);
                var ipStr = ip.ToString();
                ushort localPort = (ushort)IPAddress.NetworkToHostOrder((short)row.dwLocalPort);

                if (_seenIps.TryAdd(ipStr, 0))
                {
                    _newIpChannel.Writer.TryWrite((ip, localPort));
                    _tcpDetected++;
                    OnLog?.Invoke($"[TCP/MC] New IP: {ipStr} (local port: {localPort}, PID: {row.dwOwningPid})");
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(tcpTablePtr);
        }
    }

    public void Dispose()
    {
        StopPacketCapture();
        _cts?.Cancel();
        _cts?.Dispose();
        _newIpChannel.Writer.TryComplete();
    }

    // ===== Post-block relay frequency check =====

    private void CheckRelayFrequency(IPAddress ip)
    {
        var ipStr = ip.ToString();
        var counter = _relayCounters.GetOrAdd(ipStr, _ => new RelayCounter());

        long now = Environment.TickCount64;
        long windowAge = now - Volatile.Read(ref counter.WindowStartTick);

        if (windowAge > RelayWindowMs)
        {
            // Window is complete — evaluate the final count before resetting
            int finalCount = Volatile.Read(ref counter.Count);
            // Fire exactly once per completed window (CAS ensures only one thread reports)
            if (finalCount >= _currentRelayFreqThreshold &&
                Interlocked.CompareExchange(ref counter.Reported, 1, 0) == 0)
            {
                OnLog?.Invoke($"[Watch] ⚠ High-freq relay: {ip} — {finalCount} pkts / {RelayWindowMs}ms (threshold={_currentRelayFreqThreshold})");
                OnSuspiciousRelayDetected?.Invoke(ip);
            }

            // Start a new window
            Volatile.Write(ref counter.WindowStartTick, now);
            Interlocked.Exchange(ref counter.Count, 1);
            Interlocked.Exchange(ref counter.Reported, 0);
        }
        else
        {
            Interlocked.Increment(ref counter.Count);
        }
    }

    // ===== STUN Packet Parser =====

    private static readonly Dictionary<ushort, string> StunMessageTypes = new()
    {
        [0x0001] = "Binding Request",
        [0x0101] = "Binding Success",
        [0x0111] = "Binding Error",
        [0x0003] = "Allocate Request",
        [0x0103] = "Allocate Success",
        [0x0004] = "Refresh Request",
        [0x0104] = "Refresh Success",
        [0x0006] = "Send Indication",
        [0x0007] = "Data Indication",
        [0x0008] = "CreatePermission Request",
        [0x0108] = "CreatePermission Success",
        [0x0009] = "ChannelBind Request",
        [0x0109] = "ChannelBind Success",
    };

    private const uint StunMagicCookie = 0x2112A442;

    private const ushort AttrUsername = 0x0006;
    private const ushort AttrMessageIntegrity = 0x0008;
    private const ushort AttrXorMappedAddress  = 0x0020;
    private const ushort AttrXorPeerAddress    = 0x0012;
    private const ushort AttrXorRelayedAddress = 0x0016;
    private const ushort AttrChannelNumber = 0x000C;
    private const ushort AttrData = 0x000D;
    private const ushort AttrRealm = 0x0014;
    private const ushort AttrNonce = 0x0015;
    private const ushort AttrSoftware = 0x8022;

    private void TryLogStunAttributes(byte[] payload, IPAddress remoteIp, ushort remotePort, string direction)
    {
        try
        {
            if (payload.Length < 20) return;

            uint magic = (uint)((payload[4] << 24) | (payload[5] << 16) | (payload[6] << 8) | payload[7]);
            if (magic != StunMagicCookie) return;

            ushort msgType = (ushort)((payload[0] << 8) | payload[1]);
            ushort msgLen  = (ushort)((payload[2] << 8) | payload[3]);
            if (20 + msgLen > payload.Length) return;

            string typeName = StunMessageTypes.TryGetValue(msgType, out var t) ? t : $"0x{msgType:X4}";
            string txId = BitConverter.ToString(payload, 8, 12).Replace("-", "");
            var attrs = new System.Text.StringBuilder();

            int offset = 20;
            while (offset + 4 <= 20 + msgLen)
            {
                ushort attrType = (ushort)((payload[offset] << 8) | payload[offset + 1]);
                ushort attrLen  = (ushort)((payload[offset + 2] << 8) | payload[offset + 3]);
                offset += 4;
                if (offset + attrLen > payload.Length) break;

                switch (attrType)
                {
                    case AttrUsername:
                        string username = System.Text.Encoding.UTF8.GetString(payload, offset, attrLen);
                        attrs.Append($" USERNAME={username}");
                        if (attrLen > 20 && !username.Contains(':'))
                        {
                            try
                            {
                                byte[] token = Convert.FromBase64String(username);
                                string hex = BitConverter.ToString(token, 0, Math.Min(token.Length, 32)).Replace("-", " ");
                                attrs.Append($" [MS-TOKEN({token.Length}B): {hex}]");
                            }
                            catch { }
                        }
                        break;

                    case AttrRealm:
                        attrs.Append($" REALM={System.Text.Encoding.UTF8.GetString(payload, offset, attrLen)}");
                        break;

                    case AttrNonce:
                        attrs.Append($" NONCE={System.Text.Encoding.UTF8.GetString(payload, offset, attrLen)}");
                        break;

                    case AttrSoftware:
                        attrs.Append($" SOFTWARE={System.Text.Encoding.UTF8.GetString(payload, offset, attrLen)}");
                        break;

                    case AttrChannelNumber when attrLen >= 2:
                        attrs.Append($" CHANNEL=0x{(ushort)((payload[offset] << 8) | payload[offset + 1]):X4}");
                        break;

                    case AttrXorPeerAddress    when attrLen >= 8:
                    case AttrXorMappedAddress  when attrLen >= 8:
                    case AttrXorRelayedAddress when attrLen >= 8:
                        if (payload[offset + 1] == 0x01)
                        {
                            ushort xPort = (ushort)(((payload[offset + 2] << 8) | payload[offset + 3]) ^ 0x2112);
                            uint xIp = (uint)(((payload[offset + 4] << 24) | (payload[offset + 5] << 16)
                                             | (payload[offset + 6] << 8)  | payload[offset + 7]) ^ StunMagicCookie);
                            var addr = new IPAddress(new byte[]
                                { (byte)(xIp >> 24), (byte)(xIp >> 16), (byte)(xIp >> 8), (byte)xIp });
                            string label = attrType switch
                            {
                                AttrXorPeerAddress    => "XOR-PEER",
                                AttrXorRelayedAddress => "XOR-RELAYED",
                                _                     => "XOR-MAPPED"
                            };
                            attrs.Append($" {label}={addr}:{xPort}");
                        }
                        break;

                    case AttrMessageIntegrity:
                        attrs.Append(" [HMAC-SHA1]");
                        break;

                    case AttrData:
                        attrs.Append($" DATA({attrLen}B)");
                        break;
                }

                offset += (attrLen + 3) & ~3;
            }

        }
        catch { }
    }
}
