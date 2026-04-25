# WiFuxx: C5 Autonomous Dual-Band Deauth

[![Ko-Fi](https://img.shields.io/badge/Ko--Fi-Support%20Me-FF5E5B?logo=ko-fi&logoColor=white)](https://ko-fi.com/stoke)
[![My Website](https://img.shields.io/badge/Website-stokemctoke.com-FAA307)](https://stokemctoke.com)
[![Platform: ESP32-C5](https://img.shields.io/badge/Platform-ESP32--C5-blue)](https://www.espressif.com/en/products/socs/esp32-c5)

![image](https://github.com/stokemctoke/WiFuxx/blob/main/WiFuxx_DualBand-Deauth-Firmware.jpg)


**WiFuxx** is a compact, autonomous deauthentication tool designed for the XIAO ESP32-C5. It scans for nearby Wi-Fi networks, filters by signal strength, and launches targeted deauth attacks indefinitely — all displayed on a tiny OLED screen.

---

## ⚠️ Legal Disclaimer

> **IMPORTANT:** Laws regarding Wi-Fi deauthentication vary significantly by country. In many jurisdictions, using a deauther against networks you do not own or have explicit permission to test is **illegal** and may result in criminal charges, fines, or imprisonment.
> 
> **This tool is intended for:**
> 
> - ✅ Testing your own network security
> - ✅ Educational purposes in controlled environments
> - ✅ Authorised penetration testing
> 
> **DO NOT USE on public, neighbour, or any networks without written permission.**
> 
> **By using this software, you accept full responsibility for your actions.**

---

## 📡 Features

- **⚡ Fully Autonomous** — No web interface, no control needed. Power on and it attacks indefinitely.
- **📊 Smart Targeting** — Separate signal thresholds per band: > -75 dBm (2.4GHz) and > -70 dBm (5GHz).
- **🖥️ OLED Display** — Real-time status on a 128×64 screen:
  - Per-band AP counts (2.4GHz / 5GHz)
  - Current status (IDLE / SCAN / ATTACK + elapsed time)
  - Scrolling list of target SSIDs
- **🔫 Dual-Band Support** — Attacks both 2.4 GHz and 5 GHz networks simultaneously.
- **🚀 High Performance** — Optimised channel-hopping with batch I2C display updates (~100x fewer I2C transactions vs naive approach).
- **📝 Serial Logging** — Detailed logs via USB serial for debugging.

---

## 🛠️ Hardware Required

| Component                 | Quantity | Notes                  |
| ------------------------- | -------- | ---------------------- |
| XIAO ESP32-C5             | 1        | Main controller        |
| 0.96" OLED Display (I2C)  | 1        | 128×64, SSD1306 driver |
| Breadboard & Jumper Wires | —        | For prototyping        |
| USB-C Cable               | 1        | Power and programming  |

---

## 🔌 Wiring Diagram

Connect the OLED display to the XIAO ESP32-C5 as follows:

```
XIAO ESP32-C5          OLED Display
┌─────────────┐        ┌──────────┐
│             │        │          │
│     3V3     ├───────►│   VCC    │
│             │        │          │
│     GND     ├───────►│   GND    │
│             │        │          │
│  D4 (SDA)   ├───────►│   SDA    │  (GPIO23)
│             │        │          │
│  D5 (SCL)   ├───────►│   SCL    │  (GPIO24)
│             │        │          │
└─────────────┘        └──────────┘
```

**Pin Mapping Reference:**

| XIAO Pin | GPIO   | OLED Connection |
| -------- | ------ | --------------- |
| D4 (SDA) | GPIO23 | SDA (Data)      |
| D5 (SCL) | GPIO24 | SCL (Clock)     |
| 3V3      | —      | VCC (Power)     |
| GND      | —      | Ground          |

> **Note:** Both the XIAO ESP32-C5 and most 0.96" SSD1306 OLED modules include onboard LDO (Low Drop-Out) voltage regulators, so either 3.3V or 5V can be used to power the OLED. This project runs the OLED at 5V without issue. On standard modules, the I2C signal lines (SDA/SCL) are pulled up to the regulated 3.3V rail internally, keeping them safe for the ESP32-C5's 3.3V GPIO regardless of supply voltage. Verify this is the case for your specific module before powering at 5V.

---

## 📥 Installation

### Prerequisites

- XIAO ESP32-C5 board support
- USB-C cable

> **Directory structure:** Keep ESP-IDF (the toolchain) and WiFuxx (the project) in separate locations. The instructions below use `~/Github-Repos/` — that's just where I keep my repos. Clone them wherever makes sense for your setup, and adjust the paths accordingly.
> 
> ```
> ~/Github-Repos/
>   esp-idf/                        ← toolchain
>   WiFuxx_C5-Auto-Dualband-Deauth/ ← this project
> ```

### Step 1: Install ESP-IDF v5.5.1

> ⚠️ **WiFuxx requires ESP-IDF v5.5.1 specifically.** Other versions are not guaranteed to work.

```bash
mkdir -p ~/Github-Repos && cd ~/Github-Repos
git clone --recursive --branch v5.5.1 --depth 1 https://github.com/espressif/esp-idf.git
cd esp-idf
./install.sh esp32c5
. ./export.sh
```

> The `. ./export.sh` (note the leading dot and space) sets up the required environment variables for the current shell session. You will need to re-run this each time you open a new terminal.

### Step 2: Clone WiFuxx

```bash
cd ~/Github-Repos
git clone https://github.com/stokemctoke/WiFuxx_C5-Auto-Dualband-Deauth.git
```

### Step 3: Patch the WiFi Library

A patched version of the ESP32-C5 WiFi library is required for deauth functionality. The patch file is included in the `patched_libnet` folder of this repository.

Navigate to the ESP32-C5 WiFi library directory inside your ESP-IDF installation:

```bash
cd ~/Github-Repos/esp-idf/components/esp_wifi/lib/esp32c5
```

Remove the existing library file and replace it with the patched version:

```bash
rm libnet80211.a
cp ~/Github-Repos/WiFuxx_C5-Auto-Dualband-Deauth/patched_libnet/libnet80211.a .
```

### Step 4: Build and Flash

```bash
cd ~/Github-Repos/WiFuxx_C5-Auto-Dualband-Deauth
idf.py build
idf.py -p /dev/ttyUSB0 flash monitor
```

> Replace `/dev/ttyUSB0` with your actual serial port. Also may be shown as `/dev/ttyACM0`

---

## 🎮 Operation

### Automatic Mode

WiFuxx runs autonomously from the moment it powers on:

```
SCAN (5–10s) → ATTACK (infinite) 
```

If no targets above the signal threshold are found on boot, the device waits 25 seconds and rescans until it finds targets. Once targets are found, it attacks indefinitely without stopping.

**Display status during each phase:**

| Phase  | Display                                                      |
| ------ | ------------------------------------------------------------ |
| IDLE   | Waiting to rescan (only if no targets found)                 |
| SCAN   | Scanning for networks, counting strong APs per band          |
| ATTACK | Actively deauthenticating targets (shows elapsed time in seconds) |

### OLED Display Layout

```
┌────────────────────────────────┐
│ >> PRO DEAUTHER                │  ← Title
│ 2.4G:4 5G:3                    │  ← Per-band AP counts
│ ATK 42s                        │  ← Status + elapsed time
│ NETGEAR_123                    │  ← Target 1 (scrolls if >5)
│ BT-Hub_456                     │  ← Target 2
│ Starlink_789                   │  ← Target 3
│ TP-Link_XXX                    │  ← Target 4
│ Xfinity_YYY                    │  ← Target 5
└────────────────────────────────┘
```

### Configuration Parameters

Edit these values at the top of `main.c` to customise behaviour:

```c
#define BAD_SIGNAL_THRESHOLD_24    -75   // Attack 2.4GHz APs stronger than this (dBm)
#define BAD_SIGNAL_THRESHOLD_5     -70   // Attack 5GHz APs stronger than this (dBm)
#define MAX_TARGETS                10    // Maximum APs to target
#define AUTO_SCAN_INTERVAL_SEC     25    // Seconds between retries when no targets found
#define BURST_SIZE_24GHZ           25    // Deauth frames per burst on 2.4GHz
#define BURST_SIZE_5GHZ            35    // Deauth frames per burst on 5GHz
```

---

## 📊 Serial Monitor Output

Connect via serial monitor to see detailed logs:

```bash
idf.py monitor
```

Example output:

```
I (1234) WiFuxx: Scanning for networks...
I (5678) WiFuxx: Found 15 total networks
I (5679) WiFuxx:   [0] NETGEAR_123 (CH 6, 2.4GHz, RSSI -45, MAC aa:bb:cc:dd:ee:ff)
I (5680) WiFuxx:   [1] BT-Hub_456  (CH 1, 2.4GHz, RSSI -52, MAC 11:22:33:44:55:66)
I (5681) WiFuxx: Starting infinite attack on 7 targets
I (5682) WiFuxx: DUAL-BAND ATTACK STARTED!
I (7683) WiFuxx: [2 s] Total:   4900 pkt | PPS: 2450 | Cycles: 12
I (7684) WiFuxx:   2.4GHz:   2800 pkt (1400 pps) - 4 targets
I (7685) WiFuxx:   5GHz:     2100 pkt (1050 pps) - 3 targets
```

---

## 🔧 Troubleshootingyour

| Problem             | Solution                                                                                     |
| ------------------- | -------------------------------------------------------------------------------------------- |
| OLED display blank  | Check wiring, especially SDA/SCL. Run an I2C scanner sketch to verify address.               |
| No deauth effect    | Verify promiscuous mode is enabled — check serial for `"Failed to enable promiscuous mode"`. |
| Device not scanning | Ensure Wi-Fi is initialised correctly — serial logs will show errors.                        |
| Compilation errors  | Run `idf.py fullclean` and rebuild. Ensure ESP-IDF is v5.5.1.                                |

---

## 📈 Performance

| Metric              | Value                                                |
| ------------------- | ---------------------------------------------------- |
| Packet rate         | ~2,500 packets/second (aggregate across all targets) |
| Channel switch delay| 12 ms                                                |
| Display update rate | 1 Hz (batch I2C flush, negligible CPU impact)        |
| Memory usage        | ~50 KB heap, ~500 KB flash                           |

---

## 🔮 Future Ideas

- Battery level monitoring (XIAO battery pads)
- Battery icon on OLED
- External antenna mod
- 3D printed enclosure

---

## 🙏 Credits

- Patched Libnet - [AnvilBrain](https://github.com/AnvilBrain)
- ESP-IDF framework - [Espressif](https://www.espressif.com/)
- SSD1306 Driver - Adapted from Public Domain Sources

---

## 📜 Licence

MIT Licence — see the [LICENSE](LICENSE) file for details.

---

## ⚡ Quick Start

1. Wire OLED: `VCC→3V3`, `GND→GND`, `SDA→D4`, `SCL→D5`
2. Flash with `idf.py flash monitor`
3. Watch the OLED show the intro screen, then AP counts and attack status
4. Device scans immediately on boot and attacks all targets above threshold indefinitely

> **Remember:** Only use on your own networks! 🛡️

---

>> ***WiFuxx:** Because sometimes you just need to fuxx about (with your own network)* 😉
