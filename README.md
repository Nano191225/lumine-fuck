# LumineFuck Firewall

🛡️ DNS-based Windows firewall that blocks incoming connections from specific domain suffixes via reverse DNS lookup.

## Features

- **Reverse DNS Filtering** — Automatically resolves incoming IPs via rDNS and blocks those matching configured domain suffixes (e.g. `.orangevps.com`)
- **Windows Firewall Integration** — Creates native Windows Firewall inbound block rules (no kernel driver required)
- **Real-time GUI** — Dark-themed WPF interface with live blocked-connection log, activity log, and statistics
- **On/Off Toggle** — Enable or disable protection with a single click
- **Extensible Domain List** — Add or remove blocked domain suffixes through the GUI
- **Auto-update** — Checks for updates from GitHub Releases via Velopack (delta updates supported)
- **Installer** — Inno Setup installer with optional Windows startup registration
- **CI/CD** — GitHub Actions workflow builds, signs, and publishes release assets automatically

## How It Works

1. Polls the system TCP table every 1 second for new ESTABLISHED/SYN_RECEIVED connections
2. For each unseen remote IP, performs an async reverse DNS lookup (3s timeout)
3. If the hostname ends with any blocked domain suffix, adds the IP to a Windows Firewall inbound block rule
4. All blocked IPs are consolidated into a single firewall rule for efficiency
5. Results are cached (1-hour TTL) to avoid redundant DNS queries

## Requirements

- Windows 10/11 (x64)
- .NET 8.0 Runtime (included in self-contained build)
- Administrator privileges (required for Windows Firewall access)

## Installation

### Installer
Download the latest `LumineFuck-Setup-*.exe` from [Releases](../../releases) and run it.

### Manual
Download `LumineFuck.exe` from [Releases](../../releases) and run as Administrator.

## Configuration

Blocked domain suffixes are stored in `%AppData%\LumineFuck\blocked-domains.json`.

Default blocked domains:
```json
[".orangevps.com"]
```

You can manage domains through the GUI by clicking **Manage Domains**, or edit the JSON file directly.

## Building from Source

```powershell
# Clone
git clone https://github.com/your-username/lumine-fuck.git
cd lumine-fuck

# Build
dotnet build src/LumineFuck/LumineFuck.csproj

# Publish (self-contained)
dotnet publish src/LumineFuck/LumineFuck.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o publish/
```

## Release Workflow

Push a version tag to trigger the GitHub Actions release build:

```bash
git tag v0.1.0
git push origin v0.1.0
```

The workflow will:
1. Build & publish a self-contained single-file EXE
2. Sign the EXE (if `CERTIFICATE_PFX` and `CERTIFICATE_PASSWORD` secrets are configured)
3. Package with Velopack for auto-update support
4. Build an Inno Setup installer
5. Upload all assets to the GitHub Release

### Code Signing Setup

To enable code signing, add these GitHub repository secrets:
- `CERTIFICATE_PFX` — Base64-encoded PFX certificate
- `CERTIFICATE_PASSWORD` — Certificate password

## Tech Stack

- **Language**: C# / .NET 8.0
- **UI**: WPF (Windows Presentation Foundation) with Catppuccin Mocha theme
- **Firewall**: Windows Firewall COM API (HNetCfg.FwPolicy2) via dynamic interop
- **Connection Monitoring**: GetExtendedTcpTable (iphlpapi.dll P/Invoke)
- **MVVM**: CommunityToolkit.Mvvm
- **Auto-update**: Velopack (GitHub Releases source)
- **Installer**: Inno Setup 6
- **CI/CD**: GitHub Actions

## License

See [LICENSE](LICENSE) for details.