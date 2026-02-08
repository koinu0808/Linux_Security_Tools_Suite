# -*- coding: utf-8 -*-
"""Environment helpers (WSL detection + cross-platform command building)."""

import os
import time
import shutil
import subprocess

WSL_CACHE_TTL = 5.0
_wsl_cache = {"val": None, "ts": 0}


def is_windows():
    return os.name == 'nt'


def command_exists(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def wsl_available(force: bool = False) -> bool:
    """True only if WSL can actually execute Linux commands."""
    global _wsl_cache
    now = time.time()
    if not force and _wsl_cache["val"] is not None and (now - _wsl_cache["ts"]) < WSL_CACHE_TTL:
        return bool(_wsl_cache["val"])

    if not is_windows():
        _wsl_cache.update({"val": False, "ts": now})
        return False

    def run_wsl(args, timeout=1.6):
        try:
            p = subprocess.run(
                ["wsl"] + list(args),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
            )
            return p.returncode, (p.stdout or ""), (p.stderr or "")
        except Exception as e:
            return 1, "", str(e)

    rc, out, err = run_wsl(["-l", "-q"], timeout=1.6)
    txt = (out + "\n" + err).lower()
    if rc != 0:
        val = False
    else:
        if any(k in txt for k in [
            "no installed distributions",
            "沒有安裝任何發行版",
            "not supported",
            "wsl is not enabled",
            "the subsystem is not enabled",
        ]):
            val = False
        else:
            distros = [l.strip() for l in out.splitlines() if l.strip()]
            val = bool(distros)

    if val:
        rc2, out2, err2 = run_wsl(["-e", "sh", "-lc", "echo __wsl_ok__"], timeout=1.6)
        val = (rc2 == 0 and "__wsl_ok__" in (out2 or ""))

    _wsl_cache.update({"val": bool(val), "ts": now})
    return bool(val)


def build_powershell_command_str(cmd_list):
    exe = str(cmd_list[0]).lower()
    args = [str(x) for x in cmd_list[1:]]

    def q(s: str) -> str:
        # escape for a PowerShell double-quoted string
        return str(s).replace('"', '`"')

    if exe in ("ls", "dir"):
        path = "." if not args else (args[-1] if not args[-1].startswith("-") else ".")
        return (
            f"Get-ChildItem -Force -LiteralPath \"{q(path)}\" | "
            "Select-Object @{Name='Mode';Expression={$_.Mode}},"
            "@{Name='LastWriteTime';Expression={$_.LastWriteTime}},"
            "@{Name='Length';Expression={$_.Length}},"
            "@{Name='Name';Expression={$_.Name}} | Format-Table -AutoSize | Out-String -Width 4096"
        )

    if exe == "cat":
        path = args[-1] if args else "."
        return f"Get-Content -Raw -LiteralPath \"{q(path)}\""

    if exe == "whoami":
        return "whoami"

    if exe == "ping":
        cnt = "4"
        host = args[-1] if args else "8.8.8.8"
        for i, a in enumerate(args):
            if a in ("-c", "-n") and i + 1 < len(args):
                cnt = args[i + 1]
        return f"ping -n {q(cnt)} {q(host)}"

    if exe in ("traceroute", "tracepath"):
        host = args[-1] if args else "8.8.8.8"
        return f"tracert {q(host)}"

    if exe in ("dig",):
        host = args[-1] if args else "example.com"
        return f"nslookup {q(host)}"

    return " ".join([q(str(x)) for x in cmd_list])


def build_final_command(cmd_list, use_wsl: bool = False):
    cmd_list = list(cmd_list)
    if not cmd_list:
        return cmd_list

    if use_wsl and is_windows() and wsl_available():
        if str(cmd_list[0]).lower() != 'wsl':
            return ['wsl'] + cmd_list
        return cmd_list

    if is_windows() and not use_wsl:
        exe = str(cmd_list[0]).lower()
        external = {"nmap","ncat","nc","hydra","john","hashid","tcpdump","whatweb","gobuster","exiftool","curl"}
        if exe in external and command_exists(exe):
            return cmd_list
        ps = build_powershell_command_str(cmd_list)
        return ["powershell", "-NoProfile", "-Command", "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; " + ps]

    return cmd_list
