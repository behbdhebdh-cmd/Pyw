#!/usr/bin/env python3
"""System-Info (ohne externe Libraries) + optional Tkinter GUI

- Nutzt nur Python-Standardbibliothek.
- Gibt Infos per print aus (CLI) oder zeigt sie in einer Tkinter-GUI an.
- Speichert nichts und sendet nichts "automatisch".

WICHTIG: Public IP + Geo (Land/Region/Stadt) sind *offline* nicht möglich.
- Nur wenn du "Public IP + Geo" aktivierst (CLI: --public, GUI: Checkbox),
  werden HTTPS-Anfragen an ipify.org und ipapi.co gemacht.

CLI Beispiele:
  python system_info.py
  python system_info.py --public
  python system_info.py --nojson
  python system_info.py --gui
  python system_info.py --selftest

Hinweis zu "SystemExit: 0":
- In echten CLI-Terminals ist das normal (Exit-Code 0 = Erfolg).
- In Notebooks/IDEs wird SystemExit manchmal als "Fehler" angezeigt.
  -> Dieses Script erkennt Notebook/IDE-Umgebungen best-effort und ruft dort KEIN sys.exit() auf.
"""

from __future__ import annotations

import argparse
import json
import locale
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def run_cmd(cmd: List[str], timeout: int = 10) -> Tuple[int, str, str]:
    """Run a command safely and return (returncode, stdout, stderr)."""
    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except FileNotFoundError:
        return 127, "", f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", "Command timed out"
    except Exception as e:
        return 1, "", f"Command error: {e}"


def safe_get_outbound_local_ip() -> Optional[str]:
    """Best-effort LAN IP (no data sent; UDP connect used to pick interface).

    NOTE: For UDP sockets, connect() does not send a packet; it only selects the route/interface.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Routing hint; no payload sent.
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


def get_local_ips() -> List[str]:
    ips: List[str] = []

    # Hostname-based
    try:
        host = socket.gethostname()
        for fam, _, _, _, sockaddr in socket.getaddrinfo(host, None):
            if fam == socket.AF_INET:
                ip = sockaddr[0]
                if ip and not ip.startswith("127."):
                    ips.append(ip)
    except Exception:
        pass

    # Outbound interface hint
    out_ip = safe_get_outbound_local_ip()
    if out_ip:
        ips.append(out_ip)

    # Dedupe, preserve order
    seen = set()
    uniq: List[str] = []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            uniq.append(ip)
    return uniq


def get_mac_address() -> Optional[str]:
    try:
        node = uuid.getnode()
        mac = ":".join(f"{(node >> ele) & 0xFF:02x}" for ele in range(40, -1, -8))
        return mac
    except Exception:
        return None


def get_os_name() -> str:
    return platform.system()


def get_windows_computer_name() -> Optional[str]:
    return os.environ.get("COMPUTERNAME")


def get_hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "(unknown)"


def fetch_public_ip_and_geo(timeout: int = 6) -> Dict[str, Any]:
    """OPTIONAL external lookup. Requires internet.

    Uses:
    - https://api.ipify.org?format=json (public IP)
    - https://ipapi.co/json/ (geo by requester IP)

    Returns a dict with fields (may be partial).
    """
    import urllib.request

    out: Dict[str, Any] = {}

    # Public IP
    try:
        with urllib.request.urlopen("https://api.ipify.org?format=json", timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8", errors="replace"))
            if isinstance(data, dict):
                out["public_ip"] = data.get("ip")
    except Exception as e:
        out["public_ip_error"] = str(e)

    # Geo
    try:
        with urllib.request.urlopen("https://ipapi.co/json/", timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8", errors="replace"))
            if isinstance(data, dict):
                out["geo"] = {
                    "country": data.get("country_name") or data.get("country"),
                    "country_code": data.get("country"),
                    "region": data.get("region"),
                    "city": data.get("city"),
                    "postal": data.get("postal"),
                    "timezone": data.get("timezone"),
                    "org": data.get("org"),
                    "asn": data.get("asn"),
                }
    except Exception as e:
        out["geo_error"] = str(e)

    return out


def detect_windows_antivirus() -> List[Dict[str, Any]]:
    """Query Windows Security Center (best-effort)."""
    ps = [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | "
        "Select-Object displayName, pathToSignedProductExe, productState | ConvertTo-Json",
    ]
    rc, out, err = run_cmd(ps, timeout=12)
    if rc != 0 or not out:
        return [{"error": err or "Could not query AntiVirusProduct"}]

    try:
        data = json.loads(out)
        if isinstance(data, dict):
            return [data]
        if isinstance(data, list):
            return data
        return [{"raw": data}]
    except Exception:
        # Sometimes PowerShell prints BOM / extra text. Try to salvage JSON.
        m = re.search(r"(\{.*\}|\[.*\])", out, flags=re.S)
        if m:
            try:
                data = json.loads(m.group(1))
                if isinstance(data, dict):
                    return [data]
                if isinstance(data, list):
                    return data
            except Exception:
                pass
        return [{"raw_output": out[:2000], "stderr": err}]


def list_running_processes() -> List[str]:
    os_name = get_os_name()

    if os_name == "Windows":
        rc, out, _ = run_cmd(["tasklist"])  # built-in
        if rc == 0 and out:
            names: List[str] = []
            for line in out.splitlines()[3:]:
                parts = line.split()
                if parts:
                    names.append(parts[0].lower())
            return names
        return []

    # macOS/Linux
    rc, out, _ = run_cmd(["ps", "-A", "-o", "comm="])
    if rc == 0 and out:
        return [p.strip().lower() for p in out.splitlines() if p.strip()]
    return []


def detect_vpn_best_effort() -> Dict[str, Any]:
    os_name = get_os_name()
    procs = list_running_processes()

    vpn_process_hints = {
        "openvpn": ["openvpn"],
        "wireguard": ["wireguard", "wg", "wireguard-service", "wireguard.exe"],
        "nordvpn": ["nordvpn", "nordlynx", "nordvpn-service"],
        "expressvpn": ["expressvpn"],
        "protonvpn": ["protonvpn", "protonvpn-service"],
        "mullvad": ["mullvad", "mullvad-vpn"],
        "cisco anyconnect": ["vpnui", "anyconnect", "cisco"],
        "tailscale": ["tailscaled", "tailscale"],
        "zerotier": ["zerotier-one", "zerotier"],
    }

    found: List[str] = []
    for name, hints in vpn_process_hints.items():
        if any(h.lower() in procs for h in hints):
            found.append(name)

    info: Dict[str, Any] = {"process_hints": sorted(set(found))}

    # Interface hints (best effort)
    if os_name in ("Linux", "Darwin"):
        net_dir = Path("/sys/class/net")
        if net_dir.exists():
            ifaces = [p.name for p in net_dir.iterdir() if p.is_dir()]
            info["interfaces"] = ifaces
            vpn_ifaces = [
                i
                for i in ifaces
                if re.search(r"^(tun|tap|wg|ppp)\d*", i, re.I) or "vpn" in i.lower()
            ]
            if vpn_ifaces:
                info["interface_hints"] = vpn_ifaces

    if os_name == "Windows":
        ps = [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            "Get-NetAdapter | Select-Object Name, InterfaceDescription, Status | ConvertTo-Json",
        ]
        rc, out, err = run_cmd(ps, timeout=12)
        if rc == 0 and out:
            try:
                data = json.loads(out)
                adapters = data if isinstance(data, list) else [data]
                info["adapters"] = adapters
                joined = json.dumps(adapters).lower()
                hints: List[str] = []
                for kw in [
                    "tap",
                    "tunnel",
                    "wintun",
                    "wireguard",
                    "openvpn",
                    "vpn",
                    "nord",
                    "anyconnect",
                    "pulse",
                    "forti",
                    "tailscale",
                    "zerotier",
                ]:
                    if kw in joined:
                        hints.append(kw)
                if hints:
                    info["adapter_hints"] = sorted(set(hints))
            except Exception:
                info["adapters_error"] = err or "Could not parse adapter json"
        else:
            info["adapters_error"] = err

    return info


def detect_browsers_best_effort() -> Dict[str, Any]:
    os_name = get_os_name()
    out: Dict[str, Any] = {}

    # Known browser executables in PATH (Linux/macOS, sometimes Windows)
    candidates = [
        "google-chrome",
        "chrome",
        "chromium",
        "chromium-browser",
        "firefox",
        "brave-browser",
        "brave",
        "opera",
        "vivaldi",
        "microsoft-edge",
        "edge",
        "safari",  # rarely in PATH
    ]
    found = [c for c in candidates if shutil.which(c)]
    if found:
        out["binaries_in_path"] = found

    # Default browser detection
    if os_name == "Windows":
        rc, regout, _ = run_cmd(
            [
                "reg",
                "query",
                r"HKCU\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice",
                "/v",
                "ProgId",
            ]
        )
        if rc == 0 and regout:
            m = re.search(r"ProgId\s+REG_\w+\s+(\S+)", regout)
            if m:
                progid = m.group(1)
                out["default_http_progid"] = progid
                mapping = {
                    "ChromeHTML": "Google Chrome",
                    "MSEdgeHTM": "Microsoft Edge",
                    "FirefoxURL": "Mozilla Firefox",
                    "IE.HTTP": "Internet Explorer",
                    "OperaStable": "Opera",
                    "BraveHTML": "Brave",
                }
                for key, label in mapping.items():
                    if progid.lower().startswith(key.lower()):
                        out["default_browser_guess"] = label
                        break

    elif os_name == "Linux":
        rc, xdg, _ = run_cmd(["xdg-settings", "get", "default-web-browser"])
        if rc == 0 and xdg:
            out["default_web_browser"] = xdg

    elif os_name == "Darwin":
        apps = [
            "/Applications/Safari.app",
            "/Applications/Google Chrome.app",
            "/Applications/Firefox.app",
            "/Applications/Microsoft Edge.app",
            "/Applications/Brave Browser.app",
        ]
        present = [Path(a).name for a in apps if Path(a).exists()]
        if present:
            out["apps_present"] = present

    return out


def get_locale_info() -> Dict[str, Any]:
    # locale.getdefaultlocale() is deprecated in newer Python versions.
    try:
        loc = locale.getlocale()  # type: ignore[assignment]
    except Exception:
        loc = None

    try:
        pref_enc = locale.getpreferredencoding(False)
    except Exception:
        pref_enc = None

    return {
        "locale": loc,
        "preferred_encoding": pref_enc,
    }


def collect_info(include_public: bool = False) -> Dict[str, Any]:
    os_name = get_os_name()

    info: Dict[str, Any] = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "os": {
            "name": os_name,
            "release": platform.release(),
            "version": platform.version(),
            "platform": platform.platform(),
            "machine": platform.machine(),
            "processor": platform.processor(),
        },
        "python": {
            "version": sys.version.split()[0],
            "executable": sys.executable,
        },
        "identity": {
            "hostname": get_hostname(),
            "computer_name": get_windows_computer_name() if os_name == "Windows" else None,
            "user": os.environ.get("USERNAME") if os_name == "Windows" else os.environ.get("USER"),
            "home": str(Path.home()),
            "cwd": str(Path.cwd()),
        },
        "network": {
            "local_ips": get_local_ips(),
            "mac_address": get_mac_address(),
        },
        "locale": get_locale_info(),
        "browsers": detect_browsers_best_effort(),
        "vpn": detect_vpn_best_effort(),
    }

    if os_name == "Windows":
        info["antivirus"] = detect_windows_antivirus()
    else:
        info["antivirus"] = {
            "note": "Ohne zusätzliche Tools/Permissions ist Antivirus-Erkennung außerhalb von Windows oft unzuverlässig.",
            "process_hints": [
                p
                for p in list_running_processes()
                if any(
                    k in p
                    for k in [
                        "clam",
                        "sophos",
                        "avast",
                        "bitdefender",
                        "kaspersky",
                        "eset",
                        "crowdstrike",
                        "sentinel",
                        "defender",
                    ]
                )
            ][:50],
        }

    if include_public:
        info["public_lookup"] = fetch_public_ip_and_geo()

    return info


def info_to_json_text(info: Dict[str, Any]) -> str:
    """Stable JSON output for CLI + GUI."""
    return json.dumps(info, indent=2, ensure_ascii=False)


def pretty_print(info: Dict[str, Any]) -> None:
    print(info_to_json_text(info))


def _looks_like_notebook_or_ide() -> bool:
    """Detect notebook/IDE environments where SystemExit might be surfaced as an error.

    This is best-effort and uses only stdlib.
    """
    # Common in Jupyter
    if os.environ.get("JPY_PARENT_PID") or os.environ.get("JUPYTERHUB_USER"):
        return True

    # ipykernel module is typically loaded in notebooks
    if "ipykernel" in sys.modules:
        return True

    # Some IDEs set these env vars
    if os.environ.get("PYCHARM_HOSTED") == "1":
        return True

    return False


# --------------------------- GUI (Tkinter) ---------------------------

def run_gui(default_public: bool = False) -> int:
    """Start a small Tkinter GUI.

    - Output is shown in a text box.
    - Public lookup is opt-in.
    - Network calls run in a background thread to keep UI responsive.

    Returns an exit code.
    """
    try:
        import tkinter as tk
        from tkinter import messagebox, ttk
        from tkinter.scrolledtext import ScrolledText
    except Exception as e:
        print("Tkinter ist nicht verfügbar in dieser Python-Installation.")
        print(f"Detail: {e}")
        return 2

    root = tk.Tk()
    root.title("System-Info")
    root.minsize(860, 560)

    # State
    include_public_var = tk.BooleanVar(value=bool(default_public))
    compact_var = tk.BooleanVar(value=False)
    warn_once_var = tk.BooleanVar(value=True)

    status_var = tk.StringVar(value="Bereit")

    # Layout
    top = ttk.Frame(root, padding=10)
    top.pack(side=tk.TOP, fill=tk.X)

    body = ttk.Frame(root, padding=(10, 0, 10, 10))
    body.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

    # Controls
    ttk.Label(top, text="Optionen:").pack(side=tk.LEFT)

    cb_public = ttk.Checkbutton(top, text="Public IP + Geo (externe HTTPS-Anfrage)", variable=include_public_var)
    cb_public.pack(side=tk.LEFT, padx=(10, 0))

    cb_compact = ttk.Checkbutton(top, text="Kurzformat", variable=compact_var)
    cb_compact.pack(side=tk.LEFT, padx=(10, 0))

    cb_warn = ttk.Checkbutton(top, text="Warnung vor Public Lookup", variable=warn_once_var)
    cb_warn.pack(side=tk.LEFT, padx=(10, 0))

    btn_frame = ttk.Frame(top)
    btn_frame.pack(side=tk.RIGHT)

    # Output
    out = ScrolledText(body, wrap="word")
    out.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

    status = ttk.Label(root, textvariable=status_var, anchor="w", padding=(10, 6))
    status.pack(side=tk.BOTTOM, fill=tk.X)

    def set_output(text: str) -> None:
        out.configure(state="normal")
        out.delete("1.0", "end")
        out.insert("1.0", text)
        out.configure(state="normal")

    def format_compact(info: Dict[str, Any]) -> str:
        lines: List[str] = []
        lines.append("=== System ===")
        lines.append(f"Zeit: {info.get('timestamp')}")
        lines.append(f"OS: {info.get('os', {}).get('platform')}")
        lines.append(f"Hostname: {info.get('identity', {}).get('hostname')}")
        cn = info.get("identity", {}).get("computer_name")
        if cn:
            lines.append(f"Computername: {cn}")
        lines.append(f"User: {info.get('identity', {}).get('user')}")
        lines.append("")

        lines.append("=== Netzwerk ===")
        lines.append("Local IPs: " + (", ".join(info.get("network", {}).get("local_ips") or []) or "(none)"))
        lines.append("MAC: " + (info.get("network", {}).get("mac_address") or "(unknown)"))

        pl = info.get("public_lookup")
        if isinstance(pl, dict) and (pl.get("public_ip") or pl.get("geo")):
            lines.append("")
            lines.append("=== Public Lookup (extern) ===")
            lines.append("Public IP: " + (pl.get("public_ip") or f"(error: {pl.get('public_ip_error')})"))
            geo = pl.get("geo")
            if isinstance(geo, dict):
                lines.append("Land: " + (geo.get("country") or "(unknown)"))
                lines.append("Region: " + (geo.get("region") or "(unknown)"))
                lines.append("Stadt: " + (geo.get("city") or "(unknown)"))
            else:
                lines.append("Geo: " + f"(error: {pl.get('geo_error')})")

        lines.append("")
        lines.append("=== Browser ===")
        lines.append(json.dumps(info.get("browsers", {}), indent=2, ensure_ascii=False))

        lines.append("")
        lines.append("=== VPN (Heuristik) ===")
        lines.append(json.dumps(info.get("vpn", {}), indent=2, ensure_ascii=False))

        lines.append("")
        lines.append("=== Antivirus ===")
        lines.append(json.dumps(info.get("antivirus", {}), indent=2, ensure_ascii=False))

        return "\n".join(lines)

    def collect_and_render() -> None:
        include_public = bool(include_public_var.get())

        if include_public and warn_once_var.get():
            ok = messagebox.askokcancel(
                "Achtung: Externe Anfrage",
                "Wenn du Public IP + Geo aktivierst, macht das Script HTTPS-Anfragen an ipify.org und ipapi.co.\n\nFortfahren?",
            )
            if not ok:
                include_public_var.set(False)
                return
            # Warnung nur einmal pro Start
            warn_once_var.set(False)

        status_var.set("Sammle Infos …")

        def worker() -> None:
            try:
                info = collect_info(include_public=include_public)
                text = format_compact(info) if compact_var.get() else info_to_json_text(info)
            except Exception as e:
                text = f"Fehler beim Sammeln der Infos: {e}"

            def done() -> None:
                set_output(text)
                status_var.set("Fertig")

            root.after(0, done)

        threading.Thread(target=worker, daemon=True).start()

    def copy_to_clipboard() -> None:
        try:
            txt = out.get("1.0", "end-1c")
            root.clipboard_clear()
            root.clipboard_append(txt)
            status_var.set("In Zwischenablage kopiert")
        except Exception as e:
            messagebox.showerror("Kopieren fehlgeschlagen", str(e))

    def clear_output() -> None:
        set_output("")
        status_var.set("Bereit")

    ttk.Button(btn_frame, text="Infos holen", command=collect_and_render).pack(side=tk.LEFT, padx=(0, 8))
    ttk.Button(btn_frame, text="Kopieren", command=copy_to_clipboard).pack(side=tk.LEFT, padx=(0, 8))
    ttk.Button(btn_frame, text="Leeren", command=clear_output).pack(side=tk.LEFT, padx=(0, 8))
    ttk.Button(btn_frame, text="Beenden", command=root.destroy).pack(side=tk.LEFT)

    # Initial
    set_output(
        "Klicke auf 'Infos holen'.\n\n"
        "Hinweis: Public IP + Geo ist standardmäßig AUS und macht nur dann externe HTTPS-Anfragen."
    )

    root.mainloop()
    return 0


# --------------------------- CLI ---------------------------

def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="System-Info ausgeben (ohne externe Libraries).")
    ap.add_argument(
        "--public",
        action="store_true",
        help="OPTIONAL: Holt Public IP + Geo (macht HTTPS-Anfragen an ipify.org und ipapi.co).",
    )
    ap.add_argument(
        "--nojson",
        action="store_true",
        help="Statt JSON eine kurze Textausgabe (weniger detailliert).",
    )
    ap.add_argument(
        "--gui",
        action="store_true",
        help="Startet eine Tkinter-GUI statt Konsolen-Ausgabe.",
    )
    ap.add_argument(
        "--selftest",
        action="store_true",
        help="Führt kleine Selbsttests (unittest) aus und beendet sich danach.",
    )

    args = ap.parse_args(argv)

    if args.selftest:
        return run_selftests()

    if args.gui:
        return run_gui(default_public=args.public)

    info = collect_info(include_public=args.public)

    if not args.nojson:
        pretty_print(info)
        return 0

    # Kurzformat
    print("=== System ===")
    print(f"Zeit: {info.get('timestamp')}")
    print(f"OS: {info['os']['platform']}")
    print(f"Hostname: {info['identity']['hostname']}")
    if info["identity"].get("computer_name"):
        print(f"Computername: {info['identity']['computer_name']}")
    print(f"User: {info['identity'].get('user')}")

    print("\n=== Netzwerk ===")
    print("Local IPs:", ", ".join(info["network"].get("local_ips") or []) or "(none)")
    print("MAC:", info["network"].get("mac_address") or "(unknown)")

    if args.public:
        pl = info.get("public_lookup", {})
        print("\n=== Public Lookup (extern) ===")
        print("Public IP:", pl.get("public_ip") or f"(error: {pl.get('public_ip_error')})")
        geo = pl.get("geo")
        if isinstance(geo, dict):
            print("Land:", geo.get("country") or "(unknown)")
            print("Region:", geo.get("region") or "(unknown)")
            print("Stadt:", geo.get("city") or "(unknown)")
        else:
            print("Geo:", f"(error: {pl.get('geo_error')})")

    print("\n=== Browser ===")
    print(json.dumps(info.get("browsers", {}), indent=2, ensure_ascii=False))

    print("\n=== VPN (Heuristik) ===")
    print(json.dumps(info.get("vpn", {}), indent=2, ensure_ascii=False))

    print("\n=== Antivirus ===")
    print(json.dumps(info.get("antivirus", {}), indent=2, ensure_ascii=False))

    return 0


def run_selftests() -> int:
    """Run a small unittest suite (stdlib only)."""
    import unittest

    ipv4_re = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

    class Tests(unittest.TestCase):
        def test_collect_info_shape(self) -> None:
            info = collect_info(include_public=False)
            self.assertIsInstance(info, dict)
            for key in (
                "timestamp",
                "os",
                "python",
                "identity",
                "network",
                "locale",
                "browsers",
                "vpn",
                "antivirus",
            ):
                self.assertIn(key, info)

        def test_info_to_json_is_json(self) -> None:
            info = collect_info(include_public=False)
            s = info_to_json_text(info)
            parsed = json.loads(s)
            self.assertIsInstance(parsed, dict)
            self.assertIn("os", parsed)

        def test_local_ips_type(self) -> None:
            ips = get_local_ips()
            self.assertIsInstance(ips, list)
            for ip in ips:
                self.assertIsInstance(ip, str)
                # Not all environments have a routable IP; just validate format when present.
                self.assertTrue(bool(ipv4_re.match(ip)))

        def test_mac_format(self) -> None:
            mac = get_mac_address()
            if mac is None:
                self.skipTest("MAC address unavailable")
            self.assertIsInstance(mac, str)
            self.assertTrue(bool(re.match(r"^[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}$", mac)))

        def test_browser_dict(self) -> None:
            b = detect_browsers_best_effort()
            self.assertIsInstance(b, dict)

        def test_vpn_dict(self) -> None:
            v = detect_vpn_best_effort()
            self.assertIsInstance(v, dict)
            self.assertIn("process_hints", v)

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(Tests)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    exit_code = 0
    try:
        exit_code = main()
    except KeyboardInterrupt:
        print("\nAbgebrochen (KeyboardInterrupt).")
        exit_code = 130

    # In notebooks/IDEs avoid raising SystemExit (some show it as an exception).
    if _looks_like_notebook_or_ide():
        print(f"(Beendet mit Exit-Code {exit_code})")
    else:
        sys.exit(exit_code)
