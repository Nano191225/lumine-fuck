# LumineFuck Firewall

> [!WARNING]
> **このソフトウェアは Lumine Proxy による通信を完全にブロックするものではありません。**
> よりワールドを安全にするために、Lumine Proxy 対策のあるアンチチートの併用を検討してください。

> [!NOTE]
> **このリポジトリの 100% は AI によって生成されました。**

---

🛡️ **Minecraft 統合版（Bedrock Edition）マルチプレイ専用**の Windows ファイアウォールです。リバース DNS・ASN ルックアップ・IP/CIDR 直接指定を使って悪意ある IP を検出・ブロックします。**Windows のみ対応。**

> English: [README.md](README.md)

## 機能

### 検出

- **リバース DNS フィルタリング** — Google/Cloudflare DNS（8.8.8.8、1.1.1.1）を使って接続元 IP を PTR クエリで解決し、ホスト名が設定済みサフィックス（例: `.orangevps.com`）で終わる IP をブロック
- **IP / CIDR 直接ブロック** — rDNS 不要で特定の IP やサブネットを直接ブロック（例: `1.2.3.4`、`10.0.0.0/24`）
- **Minecraft プロセス限定** — `Minecraft.Windows`・`javaw`・`java` などの Minecraft 関連プロセスのトラフィックのみを監視し、他のアプリには影響しない
- **UDP + TCP 監視** — [Npcap](https://npcap.com/) / SharpPcap による UDP パケットキャプチャと、`GetExtendedTcpTable` P/Invoke による TCP テーブルポーリング

### ブロック

- **Windows ファイアウォール統合** — `HNetCfg.FwPolicy2` COM API 経由でネイティブ Windows ファイアウォールルールを作成（TCP/UDP × インバウンド/アウトバウンド）。カーネルドライバー不要
- **ブロック遅延** — 検出からブロックまでの遅延を設定可能（デフォルト: 5 秒）。短時間の接続を正常に完了させてからブロック
- **自動解除** — 設定した時間（デフォルト: 10 秒）が経過するとファイアウォールルールを自動削除。次の接続試行時に再検出・再ブロック
- **停止時に全解除** — 保護を無効にすると全ファイアウォールルールを削除

### GUI

- ダークテーマの WPF インターフェース（Catppuccin Mocha）
- リアルタイムの **ブロック済み接続** テーブルと **アクティビティログ**
- リアルタイム統計: ブロック済み IP 数・スキャン済み IP 数・ルール数
- **Config** ウィンドウ: ドメインサフィックス・IP/CIDR ルール・各種設定を管理
- Velopack によるアプリ内自動更新

## 動作のしくみ

```
新しい TCP/UDP 接続（Minecraft プロセスからのみ）
        ↓
1. IP/CIDR に一致？        → YES → [ブロック遅延] → ブロック
        ↓ NO
2. rDNS PTR ルックアップ   （Google/Cloudflare DNS）
   ドメインサフィックス一致？ → YES → [ブロック遅延] → ブロック
        ↓ NO
   無視

自動解除タイムアウト後:
  IP をファイアウォール + 検出キャッシュから削除 → 次の接続で再検出可能
```

## インストール

### ✅ 推奨 — 自動更新対応インストーラー

[リリース](../../releases) から **`LumineFuck-win-Setup.exe`** をダウンロードして実行してください。

Velopack によるアプリ内自動更新に対応しています。

### 動作要件

- Windows 10/11 x64
- [Npcap](https://npcap.com/#download) — UDP 監視に必須（未インストールの場合はインストーラーが案内します）
- 管理者権限（Windows ファイアウォールへのアクセスに必要。アプリは UAC で自己昇格します）

## 設定

メインウィンドウの **⚙️ Config** ボタンから設定パネルを開けます。

### ブロック対象ドメインサフィックス

rDNS のホスト名がサフィックスで終わる IP をブロックします。

デフォルト: `.orangevps.com`

設定は `%AppData%\LumineFuck\blocklist.json` に保存されます。

### ブロック対象 IP アドレス / CIDR

rDNS 不要で特定の IP やサブネットを直接ブロックします。

例: `1.2.3.4`、`20.202.59.0/24`

### 詳細設定

| 設定項目 | デフォルト | 説明 |
|---------|-----------|------|
| ブロック時に通知を表示 | ON | 接続がブロックされるたびにデスクトップ通知を表示 |
| 自動解除まで（秒） | 10 | N 秒後にファイアウォールルールを削除。0 = 自動解除しない |
| ブロック遅延（秒） | 5 | 検出後 N 秒待ってからブロック。0 = 即時ブロック |

## ソースからビルド

```powershell
# クローン
git clone https://github.com/Nano191225/lumine-fuck.git
cd lumine-fuck

# ビルド
dotnet build src/LumineFuck/LumineFuck.csproj

# 発行（自己完結型）
dotnet publish src/LumineFuck/LumineFuck.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o publish/
```

## 技術スタック

| コンポーネント | 技術 |
|--------------|------|
| 言語 | C# / .NET 8.0 |
| UI | WPF — Catppuccin Mocha テーマ |
| MVVM | CommunityToolkit.Mvvm |
| TCP 監視 | `GetExtendedTcpTable` P/Invoke (iphlpapi.dll) |
| UDP 監視 | SharpPcap 6.3 + Npcap |
| PID 解決 | `GetExtendedUdpTable` P/Invoke |
| rDNS | DnsClient.NET — Google/Cloudflare DNS 経由 PTR クエリ |
| ファイアウォール | Windows Firewall COM API (`HNetCfg.FwPolicy2`) |
| 自動更新 | Velopack（GitHub Releases） |
| インストーラー | Inno Setup 6 |
| CI/CD | GitHub Actions |

## ライセンス

詳細は [LICENSE](LICENSE) を参照してください。
