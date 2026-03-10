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
}
