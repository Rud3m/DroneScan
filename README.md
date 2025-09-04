
# DroneScan

**DroneScan** helps you detect and track drones by their Wi-Fi fingerprints. It maintains a curated list of **OUIs (Organizationally Unique Identifiers)** tied to drone manufacturers and modules, and ships tools to:

- ✅ **Generate Kismet alerts** (`devicefound=` rules) from known OUIs  
- ✅ **Scan live Wi-Fi / PCAPs** for matching **OUIs** and **SSID patterns** via a CLI tool called **`dronescan`**

> ⚠️ OUIs/SSIDs are **heuristics**, not proof. MAC randomization and renamed SSIDs can occur. Use on networks/airspace you are authorized to assess.

---

## Table of Contents

- [Why OUIs & SSIDs?](#why-ouis--ssids)
- [Quick Start](#quick-start)
- [Kismet Config Generation](#kismet-config-generation)
  - [How the mask works](#how-the-mask-works)
  - [Installing the config in Kismet](#installing-the-config-in-kismet)
- [`dronescan`: Live Wi-Fi Scanner](#dronescan-live-wi-fi-scanner)
  - [Requirements](#requirements)
  - [Usage (live & offline)](#usage)
  - [SSID rules](#ssid-rules)
- [OUI Data](#oui-data)
  - [Schema](#schema)
  - [Sample List (from this repo)](#sample-list-from-this-repo)
- [Troubleshooting](#troubleshooting)
- [Legal / Ethics](#legal--ethics)
- [License](#license)

---

## Why OUIs & SSIDs?

- An **OUI** is the first 3 bytes of a MAC address (e.g., `60:60:1F` → DJI).  
- Many drones expose MACs whose OUIs map to their **manufacturer** or to an **embedded module vendor**.  
- Many also broadcast **predictable SSIDs** (e.g., `DJI-xxxx`, `TELLO`, `Bebop2`).  
- Combining **OUI hits** with **SSID pattern matches** provides a stronger detection signal.

---


## Quick Start

```bash
# (optional) Use a virtualenv
python3 -m venv .venv && source .venv/bin/activate

# Generate the Kismet config from current OUIs
python tools/generate_kismet_config.py

# Run the live scanner (requires monitor-mode interface & airodump-ng)
sudo python tools/dronescan.py --iface wlan0mon

````

---

## Kismet Config Generation

Kismet supports `devicefound=` rules to alert on MAC masks. This repo **generates** a config with one rule per OUI.

```bash
python tools/generate_kismet_config.py
# writes: conf/oui_alerts.conf
```

Each rule looks like:

```
devicefound=60:60:1F:00:00:00/FF:FF:FF:00:00:00
```

### How the mask works

* The right side is a **bitmask** indicating which hex pairs must match.
* `FF:FF:FF:00:00:00` ⇒ “match the first 3 bytes” (the OUI).
* This covers all MACs that start with that OUI.

### Installing the config in Kismet

**System-wide include:**

```bash
sudo cp conf/oui_alerts.conf /etc/kismet/oui_alerts.conf

# add to include to /etc/kismet/kismet.conf
include=/etc/kismet/oui_alerts.conf
```

Restart Kismet. When a device with a matching OUI is observed, **DEVICEFOUND** alerts will trigger.

---

## `dronescan`: Live Wi-Fi Scanner

`dronescan` is a lightweight CLI that watches Wi-Fi **management frames** and raises alerts when:

* a device’s **OUI** matches `data/oui_drones.csv` (and optionally `data/oui_modules.csv`)
* an **SSID** matches any regex in `rules/ssids.yml`

### Requirements

* **airodump-ng** available in `$PATH`
* For live capture: a **monitor-mode** interface (e.g., `wlan0mon`)


```bash
# Debian/Ubuntu
sudo apt-get install aircrack-ng

```

### Usage

```bash
# Hop 2.4 GHz automatically (band bg), refresh CSV every 2s
sudo python tools/dronescan.py --iface wlan0mon --band bg --write-interval 2

# Lock to specific channels (comma-separated)
sudo python tools/dronescan.py --iface wlan0mon --channels 1,6,11

# Save alerts to JSONL as well
sudo python tools/dronescan.py --iface wlan0mon --band bg --jsonl sightings.jsonl

# Include module-vendor OUIs (may increase false positives)
sudo python tools/dronescan.py --iface wlan0mon --band bg --include-modules

```

### Output format

**Console example:**

```
[INFO] dronescan: started airodump-ng -> airodump-ng wlan0mon --output-format csv --write /tmp/dronescan_kduvhf63/scan --write-interval 2
[INFO] loaded 21 OUIs and 11 SSID patterns
[INFO] csv prefix: /tmp/dronescan_kduvhf63/scan-NN.csv (interval 2s)
[2025-09-04T06:52:46Z] SSID_MATCH BSSID=52:C3:4D:2B:E4:87 SSID='Spark-518dcd' TAGS=DJI Spark CH=6 PWR=-69

```

**JSONL (with `--jsonl`):**

```json
{"time":"2025-09-03T19:12:05Z","severity":"OUI_MATCH","ssid":"DJI-1234","macs":["60:60:1F:AA:BB:CC"],"oui_hits":[{"mac":"60:60:1F:AA:BB:CC","oui":"60:60:1F"}],"ssid_labels":null,"source":"dronescan"}
```

### SSID rules

Edit patterns in **`rules/ssids.yml`**. Example:

```yaml
DJI Mavic:
  - "(?i)MAVIC_AIR"
  - "(?i)Mavic"
DJI Phantom:
  - "(?i)PHANTOM\\d?"
DJI Spark:
  - "(?i)Spark"
DJI Tello:
  - "(?i)TELLO"
Parrot Bebop:
  - "(?i)Bebop\\d?"
Hubsan:
  - "(?i)HUBSAN_[A-Z]{1,2}\\d+[A-Z]?"
```

> `( ?i )` makes the regex case-insensitive. Escape backslashes in YAML (e.g., `\\d`).

---

## OUI Data

Edit/add OUIs in **`data/oui_drones.csv`** (manufacturers) and **`data/oui_modules.csv`** (chip/module vendors).
The generator reads both files; by default `dronescan` loads only `oui_drones.csv` unless `--include-modules` is set.

### Schema

**CSV columns (both files):**

| column       | description                                                   | example                          |
| ------------ | ------------------------------------------------------------- | -------------------------------- |
| `vendor`     | Company/brand name                                            | `SZ DJI TECHNOLOGY CO.,LTD`      |
| `oui`        | OUI in `XX:XX:XX` format (uppercase hex)                      | `60:60:1F`                       |
| `source_url` | Where you verified the OUI (IEEE/vendor docs/teardowns/PCAPs) | `https://standards-oui.ieee.org` |
| `notes`      | Optional context (models, region, interface notes, caveats)   | `Seen in Mavic series`           |

Validate before committing:

```bash
python tools/validate_ouis.py
```

### Sample List (from this repo)

> Full list: see **[`data/oui_drones.csv`](./data/oui_drones.csv)**.
> Below is a sample snapshot of the vendor prefixes currently included.

| Vendor                    | OUI(s)                                                                                         |
| ------------------------- | ---------------------------------------------------------------------------------------------- |
| SZ DJI TECHNOLOGY CO.,LTD | `04:A8:5A`, `0C:9A:E6`, `34:D2:62`, `48:1C:B9`, `58:B8:58`, `60:60:1F`, `8C:58:23`, `E4:7A:2C` |
| DJI BAIWANG TECH CO LTD   | `9C:5A:8A`                                                                                     |
| Autel Robotics            | `EC:5B:CD`                                                                                     |
| PARROT SA                 | `00:12:1C`, `00:26:7E`, `90:03:B7`, `90:3A:E6`, `A0:14:3D`                                     |
| Skydio Inc.               | `38:1D:14`                                                                                     |
| AeroVironment             | `00:1A:F9`                                                                                     |
| Aeryon Labs               | `70:B3:D5` *(umbrella block; sub-allocs may exist)*                                            |
| Anduril                   | `8C:1F:64` *(umbrella block; sub-allocs may exist)*                                            |
| Yuneec                    | `E0:B6:F5` *(umbrella block; sub-allocs may exist)*                                            |

---

## Troubleshooting

* **No live results?** Ensure your adapter supports **monitor mode** and is on the correct channel/band.
* **Kismet not loading rules?** Confirm `include=.../oui_alerts.conf` is present in the active `kismet.conf`.

---

## Legal / Ethics

Use this project for **defense and authorized research** only. Comply with local laws and spectrum regulations.
Fingerprinting should not be used to identify individuals or for unlawful interception.

---

## License

MIT — see `LICENSE`.

---
