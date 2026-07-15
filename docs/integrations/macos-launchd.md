# macOS LaunchAgent For Warm Recall

Use this when a local agent or hook needs the Heartwood warm recall service to
survive terminal restarts on macOS.

## TCC-Safe Paths

Do not run the database, token file, or logs from Desktop, Documents, Downloads,
iCloud Drive, or other user-protected locations unless you have granted the
launcher process Full Disk Access. LaunchAgents can fail with exit `126` and
`Operation not permitted` when they try to start from a TCC-protected workspace
even though the same command works in an interactive terminal.

Prefer non-TCC application data paths:

```bash
mkdir -p "$HOME/Library/Application Support/Heartwood"
mkdir -p "$HOME/Library/Logs/Heartwood"
python -m pip install "heartwood-memory[recall,mcp]"
python -c "import sys; print(sys.executable)"
```

Store the bearer token in a file with user-only permissions instead of passing
it on argv:

```bash
umask 077
printf '%s' 'replace-with-local-secret' > "$HOME/Library/Application Support/Heartwood/recall.token"
```

## LaunchAgent Example

Save as `~/Library/LaunchAgents/com.heartwood.recall.plist`. Replace the
interpreter path with the absolute path from `python -c "import sys;
print(sys.executable)"`.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.heartwood.recall</string>

  <key>ProgramArguments</key>
  <array>
    <string>/absolute/path/to/.venv/bin/python</string>
    <string>-m</string>
    <string>heartwood.cli</string>
    <string>serve-recall</string>
    <string>--db</string>
    <string>/Users/alex/Library/Application Support/Heartwood/heartwood.db</string>
    <string>--tenant</string>
    <string>tenant:ops</string>
    <string>--host</string>
    <string>127.0.0.1</string>
    <string>--port</string>
    <string>8765</string>
    <string>--token-file</string>
    <string>/Users/alex/Library/Application Support/Heartwood/recall.token</string>
  </array>

  <key>WorkingDirectory</key>
  <string>/Users/alex/Library/Application Support/Heartwood</string>

  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>

  <key>StandardOutPath</key>
  <string>/Users/alex/Library/Logs/Heartwood/recall.out.log</string>
  <key>StandardErrorPath</key>
  <string>/Users/alex/Library/Logs/Heartwood/recall.err.log</string>
</dict>
</plist>
```

Load and verify:

```bash
launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/com.heartwood.recall.plist"
launchctl kickstart -k "gui/$(id -u)/com.heartwood.recall"
curl -s http://127.0.0.1:8765/health
```

Unload:

```bash
launchctl bootout "gui/$(id -u)/com.heartwood.recall"
```

If the service exits immediately, read
`~/Library/Logs/Heartwood/recall.err.log` first. Exit `126` plus
`Operation not permitted` usually means the plist references a TCC-protected
working directory or database path.
