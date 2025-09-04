#!/usr/bin/env python3
import csv, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"

def check_csv(path: Path) -> int:
    errs = 0
    with open(path, newline="") as f:
        r = csv.DictReader(f)
        required = {"vendor", "oui", "source_url", "notes"}
        if set(r.fieldnames) != required:
            print(f"[ERROR] {path} columns must be exactly: {sorted(required)} (got {r.fieldnames})")
            return 1
        seen = set()
        for i, row in enumerate(r, start=2):
            v = (row["vendor"] or "").strip()
            o = (row["oui"] or "").strip().upper().replace("-", ":")
            s = (row["source_url"] or "").strip()
            if not v or not o:
                print(f"[ERROR] {path}:{i} vendor and oui are required")
                errs += 1
                continue
            parts = o.split(":")
            if len(parts) != 3 or any(len(p) != 2 for p in parts):
                print(f"[ERROR] {path}:{i} bad OUI format (want XX:XX:XX): {o}")
                errs += 1
            if o in seen:
                print(f"[ERROR] {path}:{i} duplicate OUI: {o}")
                errs += 1
            seen.add(o)
            if s and not (s.startswith("http://") or s.startswith("https://")):
                print(f"[WARN ] {path}:{i} source_url should be http(s): {s}")
    return errs

def main():
    total = 0
    for name in ("oui_drones.csv", "oui_modules.csv"):
        p = DATA / name
        if p.exists():
            total += check_csv(p)
    if total:
        print(f"[FAIL] validation errors: {total}")
        sys.exit(1)
    print("[OK] validation passed")

if __name__ == "__main__":
    main()
