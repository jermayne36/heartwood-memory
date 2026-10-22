"""Two real Herdr panes, stub agents, real signed Heartwood store; no accounts.

Run with the Python environment containing this checkout and --herdr /path/to/herdr.
All runtime state is confined to a newly created temporary directory.
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--herdr", required=True)
    args = parser.parse_args()
    binary = str(Path(args.herdr).resolve(strict=True))
    plugin = Path(__file__).parent.resolve()
    # Keep the Unix socket below the macOS sockaddr_un path-length limit.
    root = Path(tempfile.mkdtemp(prefix="hw-herdr-", dir="/tmp"))
    repo = root / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    env = {**os.environ, "XDG_CONFIG_HOME": str(root / "config"),
           "XDG_STATE_HOME": str(root / "state"), "HERDR_BIN_PATH": binary,
           "PATH": str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"]}
    env.pop("HERDR_SOCKET_PATH", None)
    # Only the explicit test socket is addressed. Never attach to the user's session.
    def call(*parts, quiet=False):
        result = subprocess.run([binary, *parts], env=env, check=True,
                                capture_output=True, text=True, timeout=30)
        if not quiet:
            print("$ herdr " + shlex.join(parts), flush=True)
            print(result.stdout.strip() or "exit=0", flush=True)
        return json.loads(result.stdout)["result"] if result.stdout.startswith("{") else result.stdout

    def wait_for(condition, label):
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            value = condition()
            if value:
                print(label, flush=True)
                return value
            time.sleep(0.1)
        raise TimeoutError(label)

    (root / "config/herdr").mkdir(parents=True)
    (root / "config/herdr/config.toml").write_text(
        '[terminal]\ndefault_shell = "/bin/sh"\nshell_mode = "non_login"\n')
    call("--version")
    call("plugin", "link", str(plugin))
    config_dir = Path(call("plugin", "config-dir", "heartwood.memory", quiet=True).strip())
    (config_dir / "config.json").write_text(json.dumps({
        "repo_root": str(repo), "db_path": str(root / "shared.db"), "tenant": "tenant:smoke"}))
    env["HERDR_SOCKET_PATH"] = str(root / "config/herdr/sessions/proof/herdr.sock")
    subprocess.run(["cc", str(plugin / "smoke-agent.c"), "-o", str(root / "claude")], check=True)
    shutil.copyfile(root / "claude", root / "codex")
    (root / "codex").chmod(0o700)
    with (root / "server.log").open("w") as log:
        server = subprocess.Popen([binary, "--session", "proof", "server"], env=env,
                                  stdout=log, stderr=log)
        try:
            wait_for(lambda: Path(env["HERDR_SOCKET_PATH"]).exists(), "isolated server ready")
            workspace = call("workspace", "create", "--cwd", str(repo),
                             "--env", "HERDR_BIN_PATH=" + binary)
            first = workspace["root_pane"]["pane_id"]

            def read(pane):
                return call("pane", "read", pane, "--source", "recent-unwrapped",
                            "--lines", "80", quiet=True)

            call("pane", "run", first, shlex.quote(str(root / "claude")))
            wait_for(lambda: "STUB READY claude" in read(first), "first pane ready")
            call("agent", "prompt", first, "finish")

            def logs():
                return call("plugin", "log", "list", "--plugin", "heartwood.memory", quiet=True)["logs"]

            def committed():
                rows = logs()
                failed = [row for row in rows if row["status"] == "failed"]
                if failed:
                    raise RuntimeError(json.dumps(failed))
                return any('"remembered"' in row.get("stdout", "") for row in rows)

            wait_for(committed, "first pane signed handoff committed")
            second = call("pane", "split", first, "--direction", "right", "--cwd", str(repo),
                          "--env", "HERDR_BIN_PATH=" + binary)["pane"]["pane_id"]
            call("pane", "run", second, shlex.quote(str(root / "codex")))
            received = wait_for(
                lambda: (text if 'RECEIVED [{"id"' in (text := read(second)) else None),
                "second pane received startup recall")
            assert '"created_by": "claude"' in received
            assert "Added parser; review edge cases next" in received
            print(received, flush=True)
            def settled_logs():
                rows = logs()
                return rows if all(row["status"] != "running" for row in rows) else None

            settled = wait_for(settled_logs, "all hook processes finished")
            for row in settled:
                print(json.dumps({key: row[key] for key in
                                  ("event", "status", "exit_code", "stdout")}), flush=True)
                assert row["status"] == "succeeded", row
            from heartwood import Heartwood
            from heartwood.policy import Principal

            db = Heartwood(path=root / "shared.db", tenant="tenant:smoke")
            try:
                note = db.recall("Herdr handoff", principal=Principal("codex", "tenant:smoke"))["results"][0]
                assert note["created_by"] == "claude"
                assert note["signature_valid_at_serve"] is True
                assert note["content_hash_match_at_serve"] is True
                print(json.dumps({key: note[key] for key in
                                  ("id", "created_by", "signature_valid_at_serve",
                                   "content_hash_match_at_serve")}), flush=True)
            finally:
                db.close()
            print("HERDR_TWO_PANE_SIGNED_HANDOFF=PASS", flush=True)
            print("runtime_artifacts=" + str(root), flush=True)
        finally:
            if server.poll() is None:
                call("server", "stop")
            server.wait(timeout=30)


if __name__ == "__main__":
    main()
