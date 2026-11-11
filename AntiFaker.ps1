<#
  AntiFaker - detects Faker (o1seth's MITM proxy) during Minecraft screenshares.

  Run it on the PC the player is showing (the "clean" one) WHILE THE PLAYER IS
  CONNECTED TO THE SERVER. No administrator rights needed.

  How Faker works (read from its source code, v1.8):
    - The cheating PC creates a Wi-Fi hotspot; the clean PC connects to it and
      reaches the Internet through that PC.
    - Using WinDivert, the cheating PC diverts to its local proxy EVERY TCP
      connection that goes through it to the server port (25565 or the SRV
      port), whatever the destination IP (filter "tcp.DstPort == port", the IP
      is never checked).
    - Its artificial delay only holds back ACK packets carrying data; the
      proxy's SYN-ACK is sent immediately.

  Tests (strongest first):
    1. Bait: connect to documentation IPs (RFC 5737) that do not exist on the
       Internet, on the server port. With nothing in between this NEVER
       connects. Behind Faker it connects within milliseconds. A control port is
       tried as well: if the control also connects, the network intercepts
       everything and nobody is blamed.
    2. Latency: the server answers the TCP connection much faster than a ping to
       that same IP => the connection is answered by something on the local
       network.
    3. Network: Windows "Internet Connection Sharing" gateway, mshome.net suffix,
       locally administered gateway MAC, BSSID equal to the gateway, default
       Windows hotspot SSID, double NAT, history of hotspot networks.
    4. Faker traces on THIS PC (in case they show the wrong PC).

  Usage (prints "Checking for Faker..." and then only the result):
    irm https://raw.githubusercontent.com/Elomcraft/antifaker/main/AntiFaker.ps1 | iex
  Full step-by-step output:
    & ([scriptblock]::Create((irm https://raw.githubusercontent.com/Elomcraft/antifaker/main/AntiFaker.ps1))) -Details
    & ([scriptblock]::Create((irm https://raw.githubusercontent.com/Elomcraft/antifaker/main/AntiFaker.ps1))) -Server play.example.com
    powershell -ExecutionPolicy Bypass -File .\AntiFaker.ps1   (local copy)
#>
[CmdletBinding()]
param(
    # Server being played on (host or host:port). Optional: detected
    # automatically when the game is connected.
    [Alias("Servidor")]
    [string]$Server = "",
    # Extra ports to test with the bait.
    [Alias("Puertos")]
    [int[]]$Ports = @(),
    # Show every test while it runs.
    [switch]$Details,
    # Also save the full report to the desktop.
    [switch]$Report
)

# Keep the caller's session clean (this also runs through "irm | iex")
$script:OldEap = $ErrorActionPreference
$script:OldProgress = $ProgressPreference
$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

$script:Version = "1.2.0"
$script:Lines = New-Object System.Collections.Generic.List[string]
$script:Findings = New-Object System.Collections.Generic.List[object]

# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------
function Out-Line([string]$Text, [string]$Color = "Gray") {
    if ($Details) { Write-Host $Text -ForegroundColor $Color }
    $script:Lines.Add($Text)
}

function Out-Title([string]$Text) {
    Out-Line ""
    Out-Line ("== " + $Text + " ==") "Cyan"
}

# Level: 3 = definitive, 2 = strong, 1 = hint
function Add-Finding([int]$Level, [string]$Text) {
    $script:Findings.Add([pscustomobject]@{ Level = $Level; Text = $Text })
    switch ($Level) {
        3 { Out-Line ("  [DETECTED] " + $Text) "Red" }
        2 { Out-Line ("  [STRONG]   " + $Text) "Magenta" }
        default { Out-Line ("  [HINT]     " + $Text) "Yellow" }
    }
}

function Out-Ok([string]$Text) { Out-Line ("  [ok] " + $Text) "Green" }
function Out-Info([string]$Text) { Out-Line ("  " + $Text) "Gray" }

function Test-Cmd([string]$Name) {
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

$script:IsWin = ($env:OS -eq "Windows_NT")

# --------------------------------------------------------------------------
# Network: timed TCP connections and ping
# --------------------------------------------------------------------------

# Returns: State = Connected | Refused | Unreachable | Timeout ; Ms = time
function Measure-Tcp([string]$Ip, [int]$Port, [int]$TimeoutMs = 1500) {
    $client = New-Object System.Net.Sockets.TcpClient
    $clock = [System.Diagnostics.Stopwatch]::StartNew()
    $state = "Timeout"
    try {
        $task = $client.ConnectAsync($Ip, $Port)
        $done = $false
        try { $done = $task.Wait($TimeoutMs) } catch { $done = $true }
        $clock.Stop()
        if (-not $done) {
            $state = "Timeout"
        } elseif ($task.Status -eq "RanToCompletion" -and $client.Connected) {
            $state = "Connected"
        } else {
            $state = "Unreachable"
            $ex = $task.Exception
            while ($ex -ne $null -and -not ($ex -is [System.Net.Sockets.SocketException])) { $ex = $ex.InnerException }
            if ($ex -ne $null -and $ex.SocketErrorCode -eq [System.Net.Sockets.SocketError]::ConnectionRefused) {
                $state = "Refused"
            }
        }
    } finally {
        if ($clock.IsRunning) { $clock.Stop() }
        try { $client.Close() } catch {}
    }
    return [pscustomobject]@{ State = $state; Ms = [math]::Round($clock.Elapsed.TotalMilliseconds, 1) }
}

# Minimum over several connections (only connected/refused ones measure a round trip)
function Measure-TcpMin([string]$Ip, [int]$Port, [int]$Times = 5) {
    $best = $null
    $states = @()
    for ($i = 0; $i -lt $Times; $i++) {
        $r = Measure-Tcp $Ip $Port 2000
        $states += $r.State
        if ($r.State -eq "Connected" -or $r.State -eq "Refused") {
            if ($best -eq $null -or $r.Ms -lt $best) { $best = $r.Ms }
        } elseif ($r.State -eq "Timeout") {
            break
        }
        Start-Sleep -Milliseconds 120
    }
    return [pscustomobject]@{ Ms = $best; States = ($states | Select-Object -Unique) -join "," }
}

function Measure-PingMin([string]$Ip, [int]$Times = 5) {
    $ping = New-Object System.Net.NetworkInformation.Ping
    $best = $null
    $ttl = $null
    for ($i = 0; $i -lt $Times; $i++) {
        try {
            $r = $ping.Send($Ip, 1500)
            if ($r.Status -eq "Success") {
                if ($best -eq $null -or $r.RoundtripTime -lt $best) { $best = [double]$r.RoundtripTime }
                if ($r.Options -ne $null) { $ttl = $r.Options.Ttl }
            }
        } catch {}
        Start-Sleep -Milliseconds 100
    }
    return [pscustomobject]@{ Ms = $best; Ttl = $ttl }
}

function Resolve-Ipv4([string]$Name) {
    $ip = $null
    if ([System.Net.IPAddress]::TryParse($Name, [ref]$ip)) { return $ip.ToString() }
    try {
        $all = [System.Net.Dns]::GetHostAddresses($Name) | Where-Object { $_.AddressFamily -eq "InterNetwork" }
        if ($all) { return $all[0].ToString() }
    } catch {}
    return $null
}

function Test-Private([string]$Ip) {
    if ($Ip -match '^10\.' -or $Ip -match '^192\.168\.' -or $Ip -match '^127\.' -or $Ip -match '^169\.254\.') { return $true }
    if ($Ip -match '^172\.(\d+)\.') { $b = [int]$Matches[1]; return ($b -ge 16 -and $b -le 31) }
    if ($Ip -match '^100\.(\d+)\.') { $b = [int]$Matches[1]; return ($b -ge 64 -and $b -le 127) }
    return $false
}

# --------------------------------------------------------------------------
# Start
# --------------------------------------------------------------------------
Write-Host ""
Write-Host "Checking for Faker..." -ForegroundColor Cyan
Out-Line ("AntiFaker " + $script:Version + " - " + (Get-Date -Format "yyyy-MM-dd HH:mm:ss")) "White"
Out-Line ("Computer: " + $env:COMPUTERNAME + "   User: " + $env:USERNAME) "White"
if (-not $script:IsWin) {
    Out-Line "Warning: not Windows; only the portable network tests will run." "Yellow"
}

# --------------------------------------------------------------------------
# 0. Minecraft connections
# --------------------------------------------------------------------------
Out-Title "Minecraft connections"
$targets = New-Object System.Collections.Generic.List[object]

if ($Server -ne "") {
    $srvHost = $Server
    $srvPort = 25565
    if ($Server -match '^(.+):(\d+)$') { $srvHost = $Matches[1]; $srvPort = [int]$Matches[2] }
    elseif (Test-Cmd "Resolve-DnsName") {
        try {
            $srv = Resolve-DnsName -Name ("_minecraft._tcp." + $srvHost) -Type SRV -ErrorAction Stop |
                Where-Object { $_.Type -eq "SRV" } | Select-Object -First 1
            if ($srv) { Out-Info ("SRV: " + $srv.NameTarget + ":" + $srv.Port); $srvHost = $srv.NameTarget; $srvPort = [int]$srv.Port }
        } catch {}
    }
    $srvIp = Resolve-Ipv4 $srvHost
    if ($srvIp) {
        $targets.Add([pscustomobject]@{ Ip = $srvIp; Port = $srvPort; Source = ("-Server " + $Server) })
        Out-Info ("Given server: " + $srvHost + " -> " + $srvIp + ":" + $srvPort)
    } else {
        Out-Line ("  Could not resolve " + $srvHost) "Yellow"
    }
}

if (Test-Cmd "Get-NetTCPConnection") {
    $procs = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -match '^(javaw?|minecraft.*|lunar.*|badlion.*|feather.*)$' })
    if ($procs.Count -eq 0) {
        Out-Line "  No Java/Minecraft process is running. The player must be INSIDE the server." "Yellow"
    }
    $ids = @($procs | ForEach-Object { $_.Id })
    $conns = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { $ids -contains $_.OwningProcess })
    foreach ($c in $conns) {
        $p = $procs | Where-Object { $_.Id -eq $c.OwningProcess } | Select-Object -First 1
        $ip = [string]$c.RemoteAddress
        if ($ip -match '^::ffff:') { $ip = $ip.Substring(7) }
        if ($ip -notmatch '^\d+\.\d+\.\d+\.\d+$') { continue }
        # Web ports of Mojang/Microsoft/launchers: not the server
        if ($c.RemotePort -eq 443 -or $c.RemotePort -eq 80) { continue }
        Out-Info ($p.ProcessName + " (PID " + $c.OwningProcess + ") -> " + $ip + ":" + $c.RemotePort)
        if ($ip -match '^127\.') {
            # The game is connected to a proxy on this same PC
            $listener = Get-NetTCPConnection -State Listen -LocalPort $c.RemotePort -ErrorAction SilentlyContinue | Select-Object -First 1
            $who = ""
            if ($listener) {
                $pp = Get-CimInstance Win32_Process -Filter ("ProcessId=" + $listener.OwningProcess) -ErrorAction SilentlyContinue
                if ($pp) { $who = $pp.Name + " " + $pp.CommandLine }
            }
            if ($who -match '(?i)faker') {
                Add-Finding 3 ("Minecraft is connected to a local proxy that is Faker: " + $who)
            } else {
                Add-Finding 1 ("Minecraft is connected to a proxy on this PC (127.0.0.1:" + $c.RemotePort + "): " + $who)
            }
            continue
        }
        if (-not ($targets | Where-Object { $_.Ip -eq $ip -and $_.Port -eq $c.RemotePort })) {
            $targets.Add([pscustomobject]@{ Ip = $ip; Port = [int]$c.RemotePort; Source = $p.ProcessName })
        }
    }
    if ($procs.Count -gt 0 -and $targets.Count -eq 0) {
        Out-Line "  Minecraft is not connected to any server. Have the player join the server and run again." "Yellow"
    }
} elseif ($targets.Count -eq 0) {
    Out-Info "Connections cannot be listed on this system; use -Server."
}

# --------------------------------------------------------------------------
# 1. Bait: non-existent IPs on the server port
# --------------------------------------------------------------------------
Out-Title "1. Bait (non-existent IPs on the server port)"
$baits = @("192.0.2.1", "198.51.100.1", "203.0.113.1")
$baitPorts = New-Object System.Collections.Generic.List[int]
$baitPorts.Add(25565)
foreach ($t in $targets) { if (-not $baitPorts.Contains($t.Port)) { $baitPorts.Add($t.Port) } }
foreach ($x in $Ports) { if (-not $baitPorts.Contains($x)) { $baitPorts.Add($x) } }
$controlPort = 47321
while ($baitPorts.Contains($controlPort)) { $controlPort++ }

$control = @($baits | ForEach-Object { Measure-Tcp $_ $controlPort 1500 })
$controlConnected = @($control | Where-Object { $_.State -eq "Connected" }).Count
$script:BaitInvalid = ($controlConnected -gt 0)
if ($controlConnected -gt 0) {
    Out-Line ("  The network intercepts ANY port (control port " + $controlPort + " also connects). Bait test not valid.") "Yellow"
    Out-Line "  (Antivirus/firewall/VPN with a transparent proxy.) Check the other tests." "Yellow"
} else {
    Out-Info ("Control port " + $controlPort + ": " + (($control | ForEach-Object { $_.State }) -join ", ") + " (normal)")
    foreach ($port in $baitPorts) {
        $res = @($baits | ForEach-Object { $r = Measure-Tcp $_ $port 1500; [pscustomobject]@{ Ip = $_; State = $r.State; Ms = $r.Ms } })
        $connected = @($res | Where-Object { $_.State -eq "Connected" })
        $summary = ($res | ForEach-Object { $_.Ip + "=" + $_.State + $(if ($_.State -eq "Connected") { " " + $_.Ms + "ms" } else { "" }) }) -join "  "
        if ($connected.Count -gt 0) {
            Add-Finding 3 ("Port " + $port + ": connections to non-existent IPs succeed (" + $summary + "). Something on the network diverts the server port to a proxy: Faker.")
        } else {
            Out-Ok ("Port " + $port + ": " + $summary)
        }
    }
}

# --------------------------------------------------------------------------
# 2. Latency: connection to the server vs ping to the same IP
# --------------------------------------------------------------------------
Out-Title "2. Server latency"
$gw = $null
if (Test-Cmd "Get-NetIPConfiguration") {
    try {
        $cfg = Get-NetIPConfiguration -ErrorAction Stop | Where-Object { $_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -eq "Up" } | Select-Object -First 1
        if ($cfg) { $gw = [string](@($cfg.IPv4DefaultGateway)[0].NextHop) }
    } catch {}
}
$gwPing = $null
if ($gw) {
    $gwPing = Measure-PingMin $gw 4
    Out-Info ("Gateway " + $gw + ": ping " + $(if ($gwPing.Ms -ne $null) { [string]$gwPing.Ms + " ms" } else { "no reply" }))
}
if ($targets.Count -eq 0) {
    Out-Info "No server to measure (the player is not connected and -Server was not given)."
}
foreach ($t in $targets) {
    if (Test-Private $t.Ip) { Out-Info ($t.Ip + " is a private IP (server on the local network): not measured."); continue }
    $mc = Measure-TcpMin $t.Ip $t.Port 5
    $ref = Measure-PingMin $t.Ip 5
    $refKind = "ping"
    $refMs = $ref.Ms
    if ($refMs -eq $null) {
        # No ICMP: a closed port answers with an RST from the server itself
        foreach ($alt in @(80, 443, 22, 8080, 21, 25564)) {
            if ($alt -eq $t.Port) { continue }
            $a = Measure-TcpMin $t.Ip $alt 3
            if ($a.Ms -ne $null) { $refMs = $a.Ms; $refKind = "tcp:" + $alt; break }
        }
    }
    $txt = $t.Ip + ":" + $t.Port + "  connect " + $(if ($mc.Ms -ne $null) { [string]$mc.Ms + " ms" } else { $mc.States }) +
        "  |  reference (" + $refKind + ") " + $(if ($refMs -ne $null) { [string]$refMs + " ms" } else { "no reply" })
    if ($mc.Ms -eq $null -or $refMs -eq $null) {
        Out-Info ($txt + "  -> inconclusive")
        continue
    }
    if (($refMs - $mc.Ms) -ge 12 -and $mc.Ms -lt ($refMs * 0.45)) {
        $extra = ""
        if ($gwPing -ne $null -and $gwPing.Ms -ne $null -and $mc.Ms -le ($gwPing.Ms + 6)) { $extra = " (same as the gateway)" }
        Add-Finding 2 ($txt + " -> the server connection is answered by something on the local network" + $extra + ". Proxy in between.")
    } else {
        Out-Ok $txt
    }
}

# --------------------------------------------------------------------------
# 3. Network: another PC's hotspot
# --------------------------------------------------------------------------
Out-Title "3. Network"
$hotspotPattern = '^(DESKTOP|LAPTOP|PC|WIN)-[A-Z0-9]{5,15} \d{4}$'
if ($script:IsWin) {
    $wifiSsid = $null; $wifiBssid = $null
    try {
        if ($gw) {
            Out-Info ("Gateway: " + $gw)
            if ($gw -match '^192\.168\.137\.') {
                Add-Finding 2 ("The gateway is " + $gw + ": Windows 'Internet Connection Sharing' network (another PC is sharing its Internet).")
            }
        }
        if (Test-Cmd "Get-DnsClient") {
            $suf = @(Get-DnsClient -ErrorAction SilentlyContinue | Where-Object { $_.ConnectionSpecificSuffix -match 'mshome\.net' })
            if ($suf.Count -gt 0) { Add-Finding 2 "DNS suffix mshome.net: the network is provided by Windows Internet Connection Sharing." }
        }
        # Gateway MAC
        $gwMac = $null
        if ($gw -and (Test-Cmd "Get-NetNeighbor")) {
            $n = Get-NetNeighbor -IPAddress $gw -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($n) { $gwMac = ([string]$n.LinkLayerAddress).ToUpper().Replace("-", ":") }
        }
        if ($gwMac -and $gwMac -match '^[0-9A-F]{2}') {
            $b0 = [Convert]::ToInt32($gwMac.Substring(0, 2), 16)
            Out-Info ("Gateway MAC: " + $gwMac)
            if (($b0 -band 2) -ne 0) {
                Add-Finding 1 "The gateway MAC is 'locally administered' (virtual adapter, typical of a Windows hotspot or a guest network)."
            }
        }
        # Wi-Fi
        $wl = $null
        try { $wl = (netsh wlan show interfaces) 2>$null } catch {}
        if ($wl) {
            foreach ($l in $wl) {
                if ($l -match '^\s*SSID\s*:\s*(.+)$') { $wifiSsid = $Matches[1].Trim() }
                elseif ($l -match '^\s*(AP )?BSSID\s*:\s*(.+)$') { $wifiBssid = $Matches[2].Trim().ToUpper().Replace("-", ":") }
            }
        }
        if ($wifiSsid) {
            Out-Info ("Wi-Fi: SSID '" + $wifiSsid + "'  BSSID " + $wifiBssid)
            if ($wifiSsid -match $hotspotPattern) {
                Add-Finding 2 ("Wi-Fi '" + $wifiSsid + "' has the default name of a Windows mobile hotspot: this PC reaches the Internet through another PC.")
            }
            if ($wifiBssid -and $gwMac -and $wifiBssid -eq $gwMac) {
                Add-Finding 1 "The Wi-Fi access point and the gateway are the same device (typical of a PC acting as a hotspot)."
            }
        } else {
            Out-Info "No Wi-Fi connected (or Windows will not show it without location permission)."
        }
        # Double NAT: the second hop is another private network
        if (Test-Cmd "tracert") {
            $tr = tracert -d -h 3 -w 400 1.1.1.1 2>$null
            $hops = @()
            foreach ($l in $tr) { if ($l -match '^\s*(\d+)\s+.*?(\d+\.\d+\.\d+\.\d+)\s*$') { $hops += [pscustomobject]@{ N = [int]$Matches[1]; Ip = $Matches[2] } } }
            if ($hops.Count -gt 0) { Out-Info ("Traceroute: " + (($hops | ForEach-Object { [string]$_.N + "=" + $_.Ip }) -join "  ")) }
            $h2 = $hops | Where-Object { $_.N -eq 2 } | Select-Object -First 1
            if ($h2 -and (Test-Private $h2.Ip) -and -not ($h2.Ip -match '^100\.')) {
                Add-Finding 1 ("Double NAT: the second hop (" + $h2.Ip + ") is another private network. There is an extra PC or router between this PC and the router.")
            }
        }
        # History of networks with Windows hotspot names (last 7 days)
        $root = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles"
        if (Test-Path $root) {
            foreach ($k in Get-ChildItem $root -ErrorAction SilentlyContinue) {
                $pr = Get-ItemProperty $k.PSPath -ErrorAction SilentlyContinue
                if (-not $pr -or -not $pr.ProfileName) { continue }
                $date = $null
                if ($pr.DateLastConnected -is [byte[]] -and $pr.DateLastConnected.Length -ge 16) {
                    $b = $pr.DateLastConnected
                    try {
                        $date = Get-Date -Year ([BitConverter]::ToUInt16($b, 0)) -Month ([BitConverter]::ToUInt16($b, 2)) -Day ([BitConverter]::ToUInt16($b, 6)) `
                            -Hour ([BitConverter]::ToUInt16($b, 8)) -Minute ([BitConverter]::ToUInt16($b, 10)) -Second 0
                    } catch {}
                }
                $recent = ($date -eq $null -or $date -gt (Get-Date).AddDays(-7))
                if ($pr.ProfileName -match $hotspotPattern -and $recent) {
                    Add-Finding 1 ("Recently connected to a network with a Windows hotspot name: '" + $pr.ProfileName + "' (" + $(if ($date) { $date.ToString("yyyy-MM-dd HH:mm") } else { "date ?" }) + ").")
                }
            }
        }
    } catch {
        Out-Line ("  Error in the network test: " + $_.Exception.Message) "Yellow"
    }
} else {
    Out-Info "Windows only."
}

# --------------------------------------------------------------------------
# 4. Faker traces on this PC
# --------------------------------------------------------------------------
Out-Title "4. Faker traces on this PC"
if ($script:IsWin) {
    try {
        $folders = @()
        if ($env:APPDATA) { $folders += (Join-Path $env:APPDATA ".faker") }
        if ($env:USERPROFILE) { $folders += (Join-Path $env:USERPROFILE ".faker") }
        foreach ($c in $folders) {
            if (Test-Path $c) {
                $f = @(Get-ChildItem $c -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.Name + " (" + $_.LastWriteTime.ToString("yyyy-MM-dd HH:mm") + ")" })
                Add-Finding 3 ("Faker folder: " + $c + "  ->  " + ($f -join ", "))
            }
        }
        # Faker running
        $jp = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -match '(?i)(net\.java\.faker|faker[-_ ]?[\d.]*\.(jar|exe))' -or $_.Name -match '(?i)^faker' })
        foreach ($p in $jp) { Add-Finding 3 ("Faker running: PID " + $p.ProcessId + " " + $p.CommandLine) }
        # WinDivert driver (Faker loads it to divert traffic)
        $drv = @()
        try { $drv = @(Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '(?i)windivert' -or $_.PathName -match '(?i)windivert' }) } catch {}
        foreach ($d in $drv) {
            $txt = "WinDivert driver (" + $d.Name + ", " + $d.State + "): " + $d.PathName
            if ($d.State -eq "Running") { Add-Finding 2 ($txt + ". Used by Faker and other traffic-diverting programs.") }
            else { Add-Finding 1 ($txt + ". Installed/used at some point.") }
        }
        # Downloads and temp
        $places = @()
        if ($env:USERPROFILE) { $places += @((Join-Path $env:USERPROFILE "Downloads"), (Join-Path $env:USERPROFILE "Desktop"), (Join-Path $env:USERPROFILE "Documents")) }
        if ($env:TEMP) { $places += $env:TEMP }
        foreach ($s in $places) {
            if (-not (Test-Path $s)) { continue }
            $hits = @(Get-ChildItem $s -Recurse -Depth 2 -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match '(?i)^(faker[-_ ]?[\d.]*\.(jar|exe|zip)|WinDivert64\.sys|win_redirect\.dll)$' })
            foreach ($h in $hits) { Add-Finding 2 ("File: " + $h.FullName + " (" + $h.LastWriteTime.ToString("yyyy-MM-dd HH:mm") + ")") }
        }
        # Prefetch (administrator only)
        $pf = Join-Path $env:WINDIR "Prefetch"
        try {
            $pfh = @(Get-ChildItem $pf -Filter "FAKER*.pf" -ErrorAction Stop)
            foreach ($h in $pfh) { Add-Finding 2 ("Prefetch: " + $h.Name + " (last run " + $h.LastWriteTime.ToString("yyyy-MM-dd HH:mm") + ")") }
        } catch { Out-Info "Prefetch not readable (run as administrator to check it)." }
        # This PC sharing its Internet (it would be the cheating PC)
        if (Test-Cmd "Get-NetIPAddress") {
            $ics = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -like "192.168.137.*" })
            foreach ($i in $ics) { Add-Finding 1 ("This PC has " + $i.IPAddress + " on '" + $i.InterfaceAlias + "': it is sharing its Internet (hotspot).") }
        }
    } catch {
        Out-Line ("  Error looking for traces: " + $_.Exception.Message) "Yellow"
    }
    if (-not ($script:Findings | Where-Object { $_.Text -match '^(Faker folder|Faker running|WinDivert|File:|Prefetch|This PC)' })) {
        Out-Ok "No Faker on this PC (expected: Faker runs on the OTHER PC)."
    }
} else {
    Out-Info "Windows only."
}

# --------------------------------------------------------------------------
# Verdict (always printed)
# --------------------------------------------------------------------------
$max = 0
foreach ($h in $script:Findings) { if ($h.Level -gt $max) { $max = $h.Level } }
$strong = @($script:Findings | Where-Object { $_.Level -ge 2 }).Count
$hints = @($script:Findings | Where-Object { $_.Level -eq 1 }).Count
if ($max -ge 3) {
    $verdict = "FAKER FOUND"; $color = "Red"
} elseif ($strong -ge 2 -or ($strong -ge 1 -and $hints -ge 1)) {
    $verdict = "VERY LIKELY FAKER (this PC goes through another PC and/or a proxy answers the server connection)"; $color = "Magenta"
} elseif ($strong -ge 1 -or $hints -ge 2) {
    $verdict = "SUSPICIOUS (possible Faker, check the reasons)"; $color = "Yellow"
} else {
    $verdict = "No Faker found"; $color = "Green"
}
if ($Details) { Write-Host ""; Write-Host "== Verdict ==" -ForegroundColor Cyan }
$script:Lines.Add(""); $script:Lines.Add("== Verdict ==")
Write-Host $verdict -ForegroundColor $color
$script:Lines.Add($verdict)
if (-not $Details) {
    foreach ($h in ($script:Findings | Sort-Object Level -Descending)) {
        Write-Host ("  - " + $h.Text) -ForegroundColor Gray
    }
}
if ($script:BaitInvalid) {
    $note = "Note: this network intercepts every port (antivirus/VPN/proxy), so the main test could not run. Disable it and run again."
    Write-Host $note -ForegroundColor Yellow
    $script:Lines.Add($note)
}
if ($targets.Count -eq 0) {
    $note = "Note: the player is not in a server, so only the default port 25565 was tested. Have them join the server and run it again."
    Write-Host $note -ForegroundColor Yellow
    $script:Lines.Add($note)
}

if ($Report -and $script:IsWin) {
    try {
        $desk = [Environment]::GetFolderPath("Desktop")
        $path = Join-Path $desk ("AntiFaker_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".txt")
        $script:Lines | Set-Content -Path $path -Encoding UTF8
        Write-Host ("Report saved to " + $path) -ForegroundColor White
    } catch {}
}
Write-Host ""

$ErrorActionPreference = $script:OldEap
$ProgressPreference = $script:OldProgress
