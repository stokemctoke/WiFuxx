# WiFuxx - ESP32-C5 Autonomous Dual-Band Deauth

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform: ESP32-C5](https://img.shields.io/badge/Platform-ESP32--C5-blue)](https://www.espressif.com/en/products/socs/esp32-c5)
[![My Website](https://img.shields.io/badge/Website-stokemctoke.com-FAA307)](https://stokemctoke.com)

![image](https://github.com/stokemctoke/WiFuxx/blob/main/WiFuxx_DualBand-Deauth-Firmware.jpg)


**WiFuxx** is a compact, autonomous deauthentication tool designed for the XIAO ESP32-C5. It scans for nearby Wi-Fi networks, filters by signal strength, and launches targeted deauth attacks — all displayed on a tiny OLED screen.

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

- **⚡ Fully Autonomous** — No web interface, no control needed. Power on and it works.
- **📊 Smart Targeting** — Only attacks APs with signal > -70 dBm (strongest nearby networks).
- **🖥️ OLED Display** — Real-time status on a 128×64 screen:
  - Number of detected APs
  - Current status (IDLE / SCAN / ATTACK)
  - Scrolling list of target SSIDs
- **🔫 Dual-Band Support** — Attacks both 2.4 GHz and 5 GHz networks.
- **🚀 High Performance** — Optimised channel-hopping attack pattern.
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
>   esp-idf/       ← toolchain
>   WiFuxx/        ← this project
> ```

### Step 1: Install ESP-IDF v5.5.1

> ⚠️ **WiFuxx requires ESP-IDF v5.5.1 specifically.** Other versions are not guaranteed to work.

```bash
mkdir -p ~/Github-Repos && cd ~/Github-Repos
git clone --recursive --branch v5.5.1 https://github.com/espressif/esp-idf.git
cd esp-idf
./install.sh
. ./export.sh
```

> The `. ./export.sh` (note the leading dot and space) sets up the required environment variables for the current shell session. You will need to re-run this each time you open a new terminal.

### Step 2: Clone WiFuxx

```bash
cd ~/Github-Repos
git clone https://github.com/stokemctoke/WiFuxx.git
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
cp ~/Github-Repos/WiFuxx/patched_libnet/libnet80211.a .
```

### Step 4: Build and Flash

```bash
cd ~/Github-Repos/WiFuxx
idf.py build
idf.py -p /dev/ttyUSB0 flash monitor
```

> Replace `/dev/ttyUSB0` with your actual serial port. Also may be shown like `/dev/ttyACM0`

---

## 🎮 Operation

### Automatic Mode

WiFuxx runs a continuous autonomous loop from the moment it powers on:

```
IDLE (30s) → SCAN (5–10s) → ATTACK (300s) → IDLE → (repeat)
```

**Display status during each phase:**

| Phase  | Display                                                 |
| ------ | ------------------------------------------------------- |
| IDLE   | Waiting for next scan cycle                             |
| SCAN   | Scanning for networks, counting strong APs              |
| ATTACK | Actively deauthenticating targets (shows packet counts) |

### OLED Display Layout

```
┌────────────────────────────────┐
│ WiFuxx                         │  ← Title
│ APs: 7                         │  ← Number of strong APs found
│ Status: ATTACK                 │  ← Current state
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
#define BAD_SIGNAL_THRESHOLD       -70    // Attack APs stronger than this (dBm)
#define MAX_TARGETS                10     // Maximum APs to target
#define AUTO_SCAN_INTERVAL_SEC     30     // Seconds between scans
#define AUTO_ATTACK_DURATION_SEC   300    // Attack duration in seconds
```

---

## 📊 Serial Monitor Output

Connect via serial monitor to see detailed logs:

```bash
idf.py monitor
```

Example output:

```
I (1234) WiFuxx: 🔍 Scanning for networks...
I (5678) WiFuxx: ✅ Found 15 total networks
I (5679) WiFuxx: 🎯 Targeting APs with signal > -70 dBm:
I (5680) WiFuxx:   [0] NETGEAR_123 (CH: 6, 2.4GHz, RSSI: -45)
I (5681) WiFuxx:   [1] BT-Hub_456  (CH: 1, 2.4GHz, RSSI: -52)
I (5682) WiFuxx: 💥 MULTI-TARGET ATTACK STARTED!
I (5683) WiFuxx: 💥 [5/300 sec] Total: 12450 pkt | PPS: 2490 | Targets: 7
```

---

## 🔧 Troubleshooting

| Problem             | Solution                                                                                     |
| ------------------- | -------------------------------------------------------------------------------------------- |
| OLED display blank  | Check wiring, especially SDA/SCL. Run an I2C scanner sketch to verify address.               |
| No deauth effect    | Verify promiscuous mode is enabled — check serial for `"Failed to enable promiscuous mode"`. |
| Device not scanning | Ensure Wi-Fi is initialised correctly — serial logs will show errors.                        |
| Compilation errors  | Run `idf.py clean` and rebuild. Ensure ESP-IDF is v5.0+.                                     |

---

## 🧪 Testing

### Safe Mode (No RF Activity)

To test the OLED and boot sequence without any RF activity:

```c
#define AUTO_MODE_ENABLED 0   // In main.c
```

This initialises all hardware but never scans or attacks — useful for verifying your wiring.

---

## 📈 Performance

| Metric              | Value                                                |
| ------------------- | ---------------------------------------------------- |
| Packet rate         | ~2,500 packets/second (aggregate across all targets) |
| Attack latency      | < 1 ms between channel switches                      |
| Display update rate | 1 Hz (negligible CPU impact)                         |
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
3. Watch the OLED show AP count and status
4. Device attacks automatically every 30 seconds

> **Remember:** Only use on your own networks! 🛡️

---

*WiFuxx — Because sometimes you need to fuxx about (with your own network 😉)*
