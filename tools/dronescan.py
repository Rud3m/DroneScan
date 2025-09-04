#!/usr/bin/env python3
"""
dronescan.py — Single-script scanner that RUNS airodump-ng, tails its CSV,
and alerts on:
  1) OUIs from data/oui_drones.csv (+ optional data/oui_modules.csv)
  2) SSIDs matching regex patterns in rules/ssids.yml

Examples:
  sudo python tools/dronescan.py --iface wlan0mon
  sudo python tools/dronescan.py --iface wlan0mon --jsonl sightings.jsonl
  sudo python tools/dronescan.py --iface wlan0mon --include-modules --band bg
  sudo python tools/dronescan.py --iface wlan0mon --channels 1,6,11 --write-interval 2

Notes:
  - You must have a monitor-mode interface ready (e.g., airmon-ng start wlan0).
  - This tool spawns airodump-ng and watches the freshest CSV it generates.
  - Cleanly terminates airodump-ng on Ctrl+C.
"""

import argparse
import csv
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml  # Optional; if missing, a tiny fallback parser is used.
    HAVE_YAML = True
except Exception:
    HAVE_YAML = False

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
RULES_DIR = ROOT / "rules"

# ---------------------------
# Data loading
# ---------------------------
def load_ouis(include_modules: bool) -> set[str]:
    """Load OUIs from CSVs; returns set of 'XX:XX:XX'."""
    ouis = set()
    sources = ["oui_drones.csv"]
    if include_modules:
        sources.append("oui_modules.csv")
    for name in sources:
        p = DATA_DIR / name
        if not p.exists():
            continue
        with open(p, newline="", encoding="utf-8") as f:
            r = csv.DictReader(f)
            for row in r:
                oui = (row.get("oui") or "").strip().upper().replace("-", ":")
                parts = oui.split(":")
                if len(parts) == 3 and all(len(x) == 2 for x in parts):
                    ouis.add(":".join(parts))
    return ouis

def fallback_parse_ssid_yaml(text: str) -> dict[str, list[str]]:
    """Extremely small YAML-ish parser for map->list of strings (quoted) only."""
    out: dict[str, list[str]] = {}
    label = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line and not line.startswith("-"):
            label = line.split(":", 1)[0].strip()
            out[label] = []
        elif line.startswith("-") and label:
            val = line[1:].strip()
            # Strip wrapping quotes if present
            if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                val = val[1:-1]
            out[label].append(val)
    return out

def load_ssid_rules() -> dict[str, list[re.Pattern]]:
    """Load SSID regex patterns from rules/ssids.yml; returns dict[label]->list[compiled regex]."""
    path = RULES_DIR / "ssids.yml"
    rules = defaultdict(list)
    if not path.exists():
        return dict(rules)
    text = path.read_text(encoding="utf-8", errors="ignore")
    if HAVE_YAML:
        obj = yaml.safe_load(text) or {}
    else:
        obj = fallback_parse_ssid_yaml(text)
    for label, patterns in (obj or {}).items():
        if not patterns:
            continue
        for pat in patterns:
            try:
                rules[label].append(re.compile(pat, re.IGNORECASE))
            except re.error as e:
                print(f"[WARN] Bad regex for '{label}': {pat} ({e})", file=sys.stderr)
    return dict(rules)

# ---------------------------
# Helpers
# ---------------------------
def mac_to_oui(mac: str) -> str:
    mac = (mac or "").strip().upper().replace("-", ":")
    if len(mac) != 17 or mac.count(":") != 5:
        return ""
    return ":".join(mac.split(":")[:3])

def latest_csv(prefix: Path) -> Path | None:
    """
    Find the newest airodump CSV matching <prefix>-NN.csv.
    """
    parent = prefix.parent
    stem = prefix.name
    candidates = sorted(parent.glob(f"{stem}-*.csv"), key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0] if candidates else None

def parse_airodump_csv(path: Path) -> list[dict]:
    """
    Parse the AP table from an airodump-ng CSV (first section).
    Returns list of dicts: {bssid, essid, channel, power, first_seen, last_seen}
    """
    aps = []
    try:
        with open(path, newline="", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f)
            header_seen = False
            for row in reader:
                if not row:
                    # Blank line -> likely end of AP section
                    if header_seen:
                        break
                    continue
                if row[0].strip().upper().startswith("BSSID"):
                    header_seen = True
                    continue
                if not header_seen:
                    continue
                # Airodump AP columns: BSSID, First time seen, Last time seen, channel, Speed, Privacy,
                # Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
                if len(row) < 14:
                    continue
                bssid = (row[0] or "").strip().upper()
                first_seen = (row[1] or "").strip()
                last_seen = (row[2] or "").strip()
                channel = (row[3] or "").strip()
                power = (row[8] or "").strip()
                essid = (row[13] or "").strip()
                aps.append({
                    "bssid": bssid,
                    "essid": essid,
                    "channel": channel,
                    "power": power,
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                })
    except FileNotFoundError:
        pass
    return aps

# ---------------------------
# Airodump management
# ---------------------------
class AirodumpRunner:
    def __init__(self, iface: str, prefix: Path, band: str | None, channels: str | None, write_interval: int, airodump_bin: str):
        self.iface = iface
        self.prefix = prefix
        self.band = band
        self.channels = channels
        self.write_interval = write_interval
        self.airodump_bin = airodump_bin
        self.proc: subprocess.Popen | None = None

    def start(self):
        cmd = [self.airodump_bin, self.iface, "--output-format", "csv", "--write", str(self.prefix), "--write-interval", str(self.write_interval)]
        # Channel plan: either --channels list OR --band (bg/a/bg/abg)
        if self.channels:
            cmd += ["--channel", self.channels]
        elif self.band:
            cmd += ["--band", self.band]
        # Run with lower priority to be nice
        self.proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, text=False)
        return cmd

    def stop(self):
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
            except Exception:
                pass

# ---------------------------
# Main
# ---------------------------
def main():
    ap = argparse.ArgumentParser(description="dronescan (airodump-ng backend): OUI & SSID alerting")
    ap.add_argument("--iface", required=True, help="Monitor-mode interface (e.g., wlan0mon)")
    ap.add_argument("--band", choices=["a", "b", "g", "bg", "abg"], help="Airodump band hopping (e.g., bg)")
    ap.add_argument("--channels", help="Comma-separated channel list (e.g., 1,6,11 or 36,40,44). Overrides --band.")
    ap.add_argument("--write-interval", type=int, default=2, help="CSV refresh interval in seconds (default: 2)")
    ap.add_argument("--include-modules", action="store_true", help="Also include OUIs from data/oui_modules.csv")
    ap.add_argument("--jsonl", help="Write JSONL alerts to this file")
    ap.add_argument("--dedup-secs", type=int, default=120, help="Suppress identical alerts within N seconds (default: 120)")
    ap.add_argument("--airodump-bin", default="airodump-ng", help="Path to airodump-ng (default: airodump-ng)")
    ap.add_argument("--prefix", help="Custom CSV prefix (directory/file). Default: temp dir.")
    ap.add_argument("--quiet", action="store_true", help="Suppress console alerts (still writes JSONL if set)")
    args = ap.parse_args()

    # Load data
    ouis = load_ouis(include_modules=args.include_modules)
    ssid_rules = load_ssid_rules()

    # Prepare output and state
    jsonl_f = open(args.jsonl, "a", buffering=1) if args.jsonl else None
    last_emit: dict[tuple, float] = {}  # key->timestamp for de-dup
    def should_emit(key: tuple, now_ts: float) -> bool:
        prev = last_emit.get(key, 0)
        if now_ts - prev >= args.dedup_secs:
            last_emit[key] = now_ts
            return True
        return False

    # Determine prefix path
    if args.prefix:
        prefix_path = Path(args.prefix).expanduser().resolve()
        prefix_path.parent.mkdir(parents=True, exist_ok=True)
    else:
        tmpdir = Path(tempfile.mkdtemp(prefix="dronescan_"))
        prefix_path = tmpdir / "scan"

    # Start airodump-ng
    runner = AirodumpRunner(
        iface=args.iface,
        prefix=prefix_path,
        band=args.band,
        channels=args.channels,
        write_interval=args.write_interval,
        airodump_bin=args.airodump_bin,
    )
    cmd = runner.start()
    if not args.quiet:
        print(f"[INFO] dronescan: started airodump-ng -> {' '.join(map(str, cmd))}")
        print(f"[INFO] loaded {len(ouis)} OUIs and {sum(len(v) for v in ssid_rules.values())} SSID patterns")
        print(f"[INFO] csv prefix: {prefix_path}-NN.csv (interval {args.write_interval}s)")

    # Graceful shutdown on Ctrl+C
    def handle_sigint(sig, frame):
        if not args.quiet:
            print("\n[INFO] stopping airodump-ng…")
        runner.stop()
        if jsonl_f:
            jsonl_f.close()
        sys.exit(0)
    signal.signal(signal.SIGINT, handle_sigint)

    # Main loop: poll newest CSV and scan
    try:
        while True:
            csv_path = latest_csv(prefix_path)
            if csv_path and csv_path.exists():
                aps = parse_airodump_csv(csv_path)
                now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
                now = time.time()
                for ap_row in aps:
                    bssid = ap_row["bssid"]
                    essid = ap_row["essid"]
                    ch = ap_row["channel"]
                    pwr = ap_row["power"]
                    if not bssid:
                        continue

                    # OUI check
                    oui = mac_to_oui(bssid)
                    oui_hit = oui in ouis if oui else False

                    # SSID regex check
                    ssid_hits = []
                    if essid:
                        for label, rxs in ssid_rules.items():
                            if any(rx.search(essid) for rx in rxs):
                                ssid_hits.append(label)

                    severity = None
                    if oui_hit and ssid_hits:
                        severity = "DRONE_CONFIRMED"
                    elif oui_hit:
                        severity = "OUI_MATCH"
                    elif ssid_hits:
                        severity = "SSID_MATCH"

                    if severity:
                        key = (severity, oui if oui_hit else "", essid)
                        if not should_emit(key, now):
                            continue
                        payload = {
                            "time": now_iso,
                            "severity": severity,
                            "bssid": bssid,
                            "channel": ch,
                            "power": pwr,
                            "ssid": essid or None,
                            "oui": oui if oui_hit else None,
                            "ssid_labels": ssid_hits or None,
                            "source": "dronescan(airodump-ng)",
                            "csv": str(csv_path),
                        }
                        if not args.quiet:
                            line = f"[{payload['time']}] {severity} BSSID={bssid}"
                            if essid:
                                line += f" SSID='{essid}'"
                            if oui_hit:
                                line += f" OUI={oui}"
                            if ssid_hits:
                                line += " TAGS=" + ",".join(ssid_hits)
                            if ch:
                                line += f" CH={ch}"
                            if pwr:
                                line += f" PWR={pwr}"
                            print(line)
                        if jsonl_f:
                            jsonl_f.write(json.dumps(payload) + "\n")
            time.sleep(args.write_interval)
    finally:
        runner.stop()
        if jsonl_f:
            jsonl_f.close()

if __name__ == "__main__":
    main()
