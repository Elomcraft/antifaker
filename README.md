# AntiFaker

Detects **Faker** ([o1seth/faker](https://github.com/o1seth/faker)) during Minecraft screenshares.

## Usage

With the player **inside the server**, on the PC they are showing, open PowerShell (Win+X → Terminal) and paste:

```powershell
irm https://raw.githubusercontent.com/Elomcraft/antifaker/main/AntiFaker.ps1 | iex
```

That's it: nothing is installed or saved. It prints `Checking for Faker...` and, after 20-60 seconds, the result:

```
Checking for Faker...
No Faker found
```

```
Checking for Faker...
FAKER FOUND
  - Port 25565: connections to non-existent IPs succeed (...). Something on the network diverts the server port to a proxy: Faker.
```

If `irm` is not recognized (you are in CMD instead of PowerShell) or you get a TLS error (older Windows 10), use this one instead. It works from CMD, Win+R or PowerShell and does not need `irm`:

```
powershell -ep bypass -c "[Net.ServicePointManager]::SecurityProtocol='Tls12'; iex (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Elomcraft/antifaker/main/AntiFaker.ps1')"
```

Requires Windows 10 or 11 (Windows 7/8 are not supported).

### Options

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/Elomcraft/antifaker/main/AntiFaker.ps1))) -Details -Server play.yourserver.com -Report
```

- `-Details`: show every test while it runs.
- `-Server host[:port]`: the server, if it is not detected automatically.
- `-Report`: also save the full report to the desktop.

## What Faker is

Faker is a man-in-the-middle proxy. The player cheats on one PC and shows the staff a second, clean PC. The clean PC reaches the Internet through the cheating PC's Wi-Fi hotspot, and Faker diverts the Minecraft connection so both clients share the same session. There is nothing of Faker to find on the clean PC, so AntiFaker looks for **what Faker does to that PC's network**.

## What it checks

| # | Test | Weight |
|---|------|--------|
| 1 | **Bait:** connects to the server port on IPs that do not exist on the Internet (192.0.2.1, 198.51.100.1, 203.0.113.1, reserved by RFC 5737). With nothing in between this never connects. Faker diverts *any* IP on that port to its proxy, so it connects within a few milliseconds. A control port is tried first: if the control connects too, the network intercepts everything and the test does not count. | **Definitive** |
| 2 | **Latency:** the TCP connection to the server is compared with a ping (or a closed port) to the same IP. Faker answers the connection from the other PC with no delay: 2-5 ms when the real server is 30+ ms away. | Strong |
| 3 | **Network:** gateway `192.168.137.x` (Windows Internet Connection Sharing), `mshome.net` suffix, default hotspot SSID (`DESKTOP-XXXXXXX 1234`), locally administered gateway MAC, BSSID equal to the gateway, double NAT, and hotspot networks used in the last 7 days. | Hints |
| 4 | **Traces on this PC** (in case they show the cheating PC): `%APPDATA%\.faker`, Faker process, WinDivert driver, `faker-*.jar/exe` files, Prefetch, and whether the PC is sharing its Internet. | Definitive / strong |

## Verdicts

- **FAKER FOUND**: the bait connected, or Faker files/process were found.
- **VERY LIKELY FAKER**: several strong findings (latency, shared-PC network...).
- **SUSPICIOUS**: loose hints; ask the player about their network.
- **No Faker found**.

## Limits

- Based on Faker 1.8 (August 2026). It is open source: if a future version limits the diversion to the server IP, test 1 will stop firing and tests 2 and 3 remain.
- Tools like ExitLag, NoPing or Proxifier, if set to divert the Minecraft port for every program, could trigger the bait. If the player uses one, close it and run again.
- The network tests are hints: some routers and guest networks use local MACs, and double NAT is common.
- Windows 11 may require location permission to read Wi-Fi details. Without it, that part is skipped.

## Safety

The script only **reads**: it installs nothing, changes no settings and sends no data anywhere (its only connections are the tests to the server, the bait IPs, 1.1.1.1 for the traceroute and the gateway). It is a single text file you can read in full before running it, and by default it writes nothing to disk.
