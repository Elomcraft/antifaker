<#
  AntiFaker - deteccion de Faker (proxy MITM de o1seth) para screenshare.

  Se ejecuta en el PC que el jugador ensena en el screenshare (el "limpio"),
  CON EL JUGADOR CONECTADO AL SERVER. No necesita administrador.

  Como funciona Faker (leido de su codigo, v1.8):
    - Un PC con el cheat crea un punto de acceso Wi-Fi; el PC limpio se conecta
      a el y sale a Internet a traves de ese PC.
    - Con WinDivert, ese PC desvia a su proxy local TODA conexion TCP que pase
      por el al puerto del server (25565 o el del SRV), sea cual sea la IP de
      destino (filtro "tcp.DstPort == puerto", sin mirar la IP).
    - Su retardo artificial solo se aplica a paquetes ACK con datos; el SYN-ACK
      del proxy sale al momento.

  Pruebas (de mas a menos fuerte):
    1. Cebo: conectar a IPs de documentacion (RFC 5737) que no existen en
       Internet, al puerto del server. Sin nada en medio, NUNCA conecta. Con
       Faker conecta en milisegundos. Se repite en un puerto de control: si el
       control tambien conecta, la red lo intercepta todo y no se acusa a nadie.
    2. Latencia: el server responde a la conexion mucho antes de lo que tarda
       un ping a esa misma IP => la conexion la contesta alguien en la red local.
    3. Red: puerta de enlace de "Conexion compartida" de Windows, sufijo
       mshome.net, MAC de la puerta de enlace administrada localmente, BSSID
       igual a la puerta de enlace, SSID por defecto de punto de acceso de
       Windows, doble NAT, historial de redes de punto de acceso.
    4. Rastros de Faker en ESTE PC (por si ensenan el PC equivocado).

  Uso:
    irm https://raw.githubusercontent.com/Elomcraft/antifaker/main/AntiFaker.ps1 | iex
    & ([scriptblock]::Create((irm https://raw.githubusercontent.com/Elomcraft/antifaker/main/AntiFaker.ps1))) -Servidor play.ejemplo.com
    powershell -ExecutionPolicy Bypass -File .\AntiFaker.ps1   (copia local)
#>
[CmdletBinding()]
param(
    # Server al que juega (host o host:puerto). Opcional: si el juego esta
    # conectado se detecta solo.
    [string]$Servidor = "",
    # Puertos extra a probar con el cebo.
    [int[]]$Puertos = @(),
    # No guardar el informe en el escritorio.
    [switch]$SinInforme
)

$ErrorActionPreference = "Continue"
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

$script:Version = "1.0.0"
$script:Lineas = New-Object System.Collections.Generic.List[string]
$script:Hallazgos = New-Object System.Collections.Generic.List[object]

# --------------------------------------------------------------------------
# Salida
# --------------------------------------------------------------------------
function Out-Linea([string]$Texto, [string]$Color = "Gray") {
    Write-Host $Texto -ForegroundColor $Color
    $script:Lineas.Add($Texto)
}

function Out-Titulo([string]$Texto) {
    Out-Linea ""
    Out-Linea ("== " + $Texto + " ==") "Cyan"
}

# Nivel: 3 = definitivo, 2 = fuerte, 1 = indicio
function Add-Hallazgo([int]$Nivel, [string]$Texto) {
    $script:Hallazgos.Add([pscustomobject]@{ Nivel = $Nivel; Texto = $Texto })
    switch ($Nivel) {
        3 { Out-Linea ("  [DETECTADO] " + $Texto) "Red" }
        2 { Out-Linea ("  [FUERTE]    " + $Texto) "Magenta" }
        default { Out-Linea ("  [INDICIO]   " + $Texto) "Yellow" }
    }
}

function Out-Ok([string]$Texto) { Out-Linea ("  [ok] " + $Texto) "Green" }
function Out-Info([string]$Texto) { Out-Linea ("  " + $Texto) "Gray" }

function Test-Cmd([string]$Nombre) {
    return [bool](Get-Command $Nombre -ErrorAction SilentlyContinue)
}

$script:EsWindows = ($env:OS -eq "Windows_NT")

# --------------------------------------------------------------------------
# Red: conexiones TCP cronometradas y ping
# --------------------------------------------------------------------------

# Devuelve: Estado = Conecta | Rechaza | Inalcanzable | Tiempo ; Ms = tiempo
function Measure-Tcp([string]$Ip, [int]$Puerto, [int]$TimeoutMs = 1500) {
    $cliente = New-Object System.Net.Sockets.TcpClient
    $reloj = [System.Diagnostics.Stopwatch]::StartNew()
    $estado = "Tiempo"
    try {
        $tarea = $cliente.ConnectAsync($Ip, $Puerto)
        $acabo = $false
        try { $acabo = $tarea.Wait($TimeoutMs) } catch { $acabo = $true }
        $reloj.Stop()
        if (-not $acabo) {
            $estado = "Tiempo"
        } elseif ($tarea.Status -eq "RanToCompletion" -and $cliente.Connected) {
            $estado = "Conecta"
        } else {
            $estado = "Inalcanzable"
            $ex = $tarea.Exception
            while ($ex -ne $null -and -not ($ex -is [System.Net.Sockets.SocketException])) { $ex = $ex.InnerException }
            if ($ex -ne $null -and $ex.SocketErrorCode -eq [System.Net.Sockets.SocketError]::ConnectionRefused) {
                $estado = "Rechaza"
            }
        }
    } finally {
        if ($reloj.IsRunning) { $reloj.Stop() }
        try { $cliente.Close() } catch {}
    }
    return [pscustomobject]@{ Estado = $estado; Ms = [math]::Round($reloj.Elapsed.TotalMilliseconds, 1) }
}

# Minimo de varias conexiones (solo las que conectan o rechazan miden ida y vuelta)
function Measure-TcpMin([string]$Ip, [int]$Puerto, [int]$Veces = 5) {
    $mejor = $null
    $estados = @()
    for ($i = 0; $i -lt $Veces; $i++) {
        $r = Measure-Tcp $Ip $Puerto 2000
        $estados += $r.Estado
        if ($r.Estado -eq "Conecta" -or $r.Estado -eq "Rechaza") {
            if ($mejor -eq $null -or $r.Ms -lt $mejor) { $mejor = $r.Ms }
        } elseif ($r.Estado -eq "Tiempo") {
            break
        }
        Start-Sleep -Milliseconds 120
    }
    return [pscustomobject]@{ Ms = $mejor; Estados = ($estados | Select-Object -Unique) -join "," }
}

function Measure-PingMin([string]$Ip, [int]$Veces = 5) {
    $ping = New-Object System.Net.NetworkInformation.Ping
    $mejor = $null
    $ttl = $null
    for ($i = 0; $i -lt $Veces; $i++) {
        try {
            $r = $ping.Send($Ip, 1500)
            if ($r.Status -eq "Success") {
                if ($mejor -eq $null -or $r.RoundtripTime -lt $mejor) { $mejor = [double]$r.RoundtripTime }
                if ($r.Options -ne $null) { $ttl = $r.Options.Ttl }
            }
        } catch {}
        Start-Sleep -Milliseconds 100
    }
    return [pscustomobject]@{ Ms = $mejor; Ttl = $ttl }
}

function Resolve-Ipv4([string]$Nombre) {
    $ip = $null
    if ([System.Net.IPAddress]::TryParse($Nombre, [ref]$ip)) { return $ip.ToString() }
    try {
        $todas = [System.Net.Dns]::GetHostAddresses($Nombre) | Where-Object { $_.AddressFamily -eq "InterNetwork" }
        if ($todas) { return $todas[0].ToString() }
    } catch {}
    return $null
}

function Test-Privada([string]$Ip) {
    if ($Ip -match '^10\.' -or $Ip -match '^192\.168\.' -or $Ip -match '^127\.' -or $Ip -match '^169\.254\.') { return $true }
    if ($Ip -match '^172\.(\d+)\.') { $b = [int]$Matches[1]; return ($b -ge 16 -and $b -le 31) }
    if ($Ip -match '^100\.(\d+)\.') { $b = [int]$Matches[1]; return ($b -ge 64 -and $b -le 127) }
    return $false
}

# --------------------------------------------------------------------------
# Inicio
# --------------------------------------------------------------------------
Out-Linea ("AntiFaker " + $script:Version + " - " + (Get-Date -Format "yyyy-MM-dd HH:mm:ss")) "White"
Out-Linea ("Equipo: " + $env:COMPUTERNAME + "   Usuario: " + $env:USERNAME) "White"
if (-not $script:EsWindows) {
    Out-Linea "Aviso: no es Windows; solo se hacen las pruebas de red portables." "Yellow"
}

# --------------------------------------------------------------------------
# 0. Conexiones de Minecraft
# --------------------------------------------------------------------------
Out-Titulo "Conexiones de Minecraft"
$destinos = New-Object System.Collections.Generic.List[object]

if ($Servidor -ne "") {
    $hostSrv = $Servidor
    $puertoSrv = 25565
    if ($Servidor -match '^(.+):(\d+)$') { $hostSrv = $Matches[1]; $puertoSrv = [int]$Matches[2] }
    elseif (Test-Cmd "Resolve-DnsName") {
        try {
            $srv = Resolve-DnsName -Name ("_minecraft._tcp." + $hostSrv) -Type SRV -ErrorAction Stop |
                Where-Object { $_.Type -eq "SRV" } | Select-Object -First 1
            if ($srv) { Out-Info ("SRV: " + $srv.NameTarget + ":" + $srv.Port); $hostSrv = $srv.NameTarget; $puertoSrv = [int]$srv.Port }
        } catch {}
    }
    $ipSrv = Resolve-Ipv4 $hostSrv
    if ($ipSrv) {
        $destinos.Add([pscustomobject]@{ Ip = $ipSrv; Puerto = $puertoSrv; Origen = ("-Servidor " + $Servidor) })
        Out-Info ("Server indicado: " + $hostSrv + " -> " + $ipSrv + ":" + $puertoSrv)
    } else {
        Out-Linea ("  No se pudo resolver " + $hostSrv) "Yellow"
    }
}

if (Test-Cmd "Get-NetTCPConnection") {
    $procs = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -match '^(javaw?|minecraft.*|lunar.*|badlion.*|feather.*)$' })
    if ($procs.Count -eq 0) {
        Out-Linea "  No hay ningun Java/Minecraft abierto. El jugador debe estar DENTRO del server." "Yellow"
    }
    $ids = @($procs | ForEach-Object { $_.Id })
    $conexiones = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { $ids -contains $_.OwningProcess })
    foreach ($c in $conexiones) {
        $p = $procs | Where-Object { $_.Id -eq $c.OwningProcess } | Select-Object -First 1
        $ip = [string]$c.RemoteAddress
        if ($ip -match '^::ffff:') { $ip = $ip.Substring(7) }
        if ($ip -notmatch '^\d+\.\d+\.\d+\.\d+$') { continue }
        # Puertos web de Mojang/Microsoft/launchers: no son el server
        if ($c.RemotePort -eq 443 -or $c.RemotePort -eq 80) { continue }
        Out-Info ($p.ProcessName + " (PID " + $c.OwningProcess + ") -> " + $ip + ":" + $c.RemotePort)
        if ($ip -match '^127\.') {
            # El juego conectado a un proxy en este mismo PC
            $escucha = Get-NetTCPConnection -State Listen -LocalPort $c.RemotePort -ErrorAction SilentlyContinue | Select-Object -First 1
            $quien = ""
            if ($escucha) {
                $pp = Get-CimInstance Win32_Process -Filter ("ProcessId=" + $escucha.OwningProcess) -ErrorAction SilentlyContinue
                if ($pp) { $quien = $pp.Name + " " + $pp.CommandLine }
            }
            if ($quien -match '(?i)faker') {
                Add-Hallazgo 3 ("Minecraft conectado a un proxy local que es Faker: " + $quien)
            } else {
                Add-Hallazgo 1 ("Minecraft conectado a un proxy en este PC (127.0.0.1:" + $c.RemotePort + "): " + $quien)
            }
            continue
        }
        if (-not ($destinos | Where-Object { $_.Ip -eq $ip -and $_.Puerto -eq $c.RemotePort })) {
            $destinos.Add([pscustomobject]@{ Ip = $ip; Puerto = [int]$c.RemotePort; Origen = $p.ProcessName })
        }
    }
    if ($procs.Count -gt 0 -and $destinos.Count -eq 0) {
        Out-Linea "  Minecraft no tiene conexion a ningun server. Que entre al server y repite." "Yellow"
    }
} elseif ($destinos.Count -eq 0) {
    Out-Info "No se pueden listar conexiones en este sistema; usa -Servidor."
}

# --------------------------------------------------------------------------
# 1. Cebo: IPs que no existen en Internet al puerto del server
# --------------------------------------------------------------------------
Out-Titulo "1. Cebo (IPs inexistentes al puerto del server)"
$cebos = @("192.0.2.1", "198.51.100.1", "203.0.113.1")
$puertosCebo = New-Object System.Collections.Generic.List[int]
$puertosCebo.Add(25565)
foreach ($d in $destinos) { if (-not $puertosCebo.Contains($d.Puerto)) { $puertosCebo.Add($d.Puerto) } }
foreach ($x in $Puertos) { if (-not $puertosCebo.Contains($x)) { $puertosCebo.Add($x) } }
$puertoControl = 47321
while ($puertosCebo.Contains($puertoControl)) { $puertoControl++ }

$control = @($cebos | ForEach-Object { Measure-Tcp $_ $puertoControl 1500 })
$controlConecta = @($control | Where-Object { $_.Estado -eq "Conecta" }).Count
if ($controlConecta -gt 0) {
    Out-Linea ("  La red intercepta CUALQUIER puerto (control " + $puertoControl + " tambien conecta). Prueba del cebo no valida.") "Yellow"
    Out-Linea "  (Antivirus/cortafuegos/VPN con proxy transparente.) Mira las demas pruebas." "Yellow"
} else {
    Out-Info ("Control puerto " + $puertoControl + ": " + (($control | ForEach-Object { $_.Estado }) -join ", ") + " (normal)")
    foreach ($pto in $puertosCebo) {
        $res = @($cebos | ForEach-Object { $r = Measure-Tcp $_ $pto 1500; [pscustomobject]@{ Ip = $_; Estado = $r.Estado; Ms = $r.Ms } })
        $conectan = @($res | Where-Object { $_.Estado -eq "Conecta" })
        $resumen = ($res | ForEach-Object { $_.Ip + "=" + $_.Estado + $(if ($_.Estado -eq "Conecta") { " " + $_.Ms + "ms" } else { "" }) }) -join "  "
        if ($conectan.Count -gt 0) {
            Add-Hallazgo 3 ("Puerto " + $pto + ": se puede conectar a IPs que no existen (" + $resumen + "). Algo en la red desvia el puerto del server a un proxy: Faker.")
        } else {
            Out-Ok ("Puerto " + $pto + ": " + $resumen)
        }
    }
}

# --------------------------------------------------------------------------
# 2. Latencia: conexion al server vs ping a la misma IP
# --------------------------------------------------------------------------
Out-Titulo "2. Latencia del server"
$gw = $null
if (Test-Cmd "Get-NetIPConfiguration") {
    try {
        $cfg = Get-NetIPConfiguration -ErrorAction Stop | Where-Object { $_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -eq "Up" } | Select-Object -First 1
        if ($cfg) { $gw = [string](@($cfg.IPv4DefaultGateway)[0].NextHop) }
    } catch {}
}
$pingGw = $null
if ($gw) {
    $pingGw = Measure-PingMin $gw 4
    Out-Info ("Puerta de enlace " + $gw + ": ping " + $(if ($pingGw.Ms -ne $null) { [string]$pingGw.Ms + " ms" } else { "sin respuesta" }))
}
if ($destinos.Count -eq 0) {
    Out-Info "Sin server que medir (el jugador no esta conectado y no se paso -Servidor)."
}
foreach ($d in $destinos) {
    if (Test-Privada $d.Ip) { Out-Info ($d.Ip + " es una IP privada (server en la red local): no se mide."); continue }
    $mc = Measure-TcpMin $d.Ip $d.Puerto 5
    $ref = Measure-PingMin $d.Ip 5
    $refTipo = "ping"
    $refMs = $ref.Ms
    if ($refMs -eq $null) {
        # Sin ICMP: un puerto cerrado contesta con RST desde el propio server
        foreach ($alt in @(80, 443, 22, 8080, 21, 25564)) {
            if ($alt -eq $d.Puerto) { continue }
            $a = Measure-TcpMin $d.Ip $alt 3
            if ($a.Ms -ne $null) { $refMs = $a.Ms; $refTipo = "tcp:" + $alt; break }
        }
    }
    $txt = $d.Ip + ":" + $d.Puerto + "  conexion " + $(if ($mc.Ms -ne $null) { [string]$mc.Ms + " ms" } else { $mc.Estados }) +
        "  |  referencia (" + $refTipo + ") " + $(if ($refMs -ne $null) { [string]$refMs + " ms" } else { "sin respuesta" })
    if ($mc.Ms -eq $null -or $refMs -eq $null) {
        Out-Info ($txt + "  -> no concluyente")
        continue
    }
    if (($refMs - $mc.Ms) -ge 12 -and $mc.Ms -lt ($refMs * 0.45)) {
        $extra = ""
        if ($pingGw -ne $null -and $pingGw.Ms -ne $null -and $mc.Ms -le ($pingGw.Ms + 6)) { $extra = " (igual que la puerta de enlace)" }
        Add-Hallazgo 2 ($txt + " -> la conexion al server la contesta algo en la red local" + $extra + ". Proxy en medio.")
    } else {
        Out-Ok $txt
    }
}

# --------------------------------------------------------------------------
# 3. Red del PC: punto de acceso de otro PC
# --------------------------------------------------------------------------
Out-Titulo "3. Red"
$patronHotspot = '^(DESKTOP|LAPTOP|PC|WIN)-[A-Z0-9]{5,15} \d{4}$'
if ($script:EsWindows) {
    $wifiSsid = $null; $wifiBssid = $null
    try {
        if ($gw) {
            Out-Info ("Puerta de enlace: " + $gw)
            if ($gw -match '^192\.168\.137\.') {
                Add-Hallazgo 2 ("La puerta de enlace es " + $gw + ": red de 'Conexion compartida a Internet' de Windows (otro PC comparte su Internet).")
            }
        }
        if (Test-Cmd "Get-DnsClient") {
            $suf = @(Get-DnsClient -ErrorAction SilentlyContinue | Where-Object { $_.ConnectionSpecificSuffix -match 'mshome\.net' })
            if ($suf.Count -gt 0) { Add-Hallazgo 2 "Sufijo DNS mshome.net: la red la da la Conexion compartida de Windows." }
        }
        # MAC de la puerta de enlace
        $macGw = $null
        if ($gw -and (Test-Cmd "Get-NetNeighbor")) {
            $n = Get-NetNeighbor -IPAddress $gw -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($n) { $macGw = ([string]$n.LinkLayerAddress).ToUpper().Replace("-", ":") }
        }
        if ($macGw -and $macGw -match '^[0-9A-F]{2}') {
            $b0 = [Convert]::ToInt32($macGw.Substring(0, 2), 16)
            Out-Info ("MAC de la puerta de enlace: " + $macGw)
            if (($b0 -band 2) -ne 0) {
                Add-Hallazgo 1 "La MAC de la puerta de enlace es 'administrada localmente' (adaptador virtual, tipico del punto de acceso de Windows o de una red de invitados)."
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
            if ($wifiSsid -match $patronHotspot) {
                Add-Hallazgo 2 ("El Wi-Fi '" + $wifiSsid + "' tiene el nombre por defecto del punto de acceso movil de Windows: el PC sale a Internet por otro PC.")
            }
            if ($wifiBssid -and $macGw -and $wifiBssid -eq $macGw) {
                Add-Hallazgo 1 "El punto de acceso Wi-Fi y la puerta de enlace son el mismo aparato (tipico de un PC haciendo de punto de acceso)."
            }
        } else {
            Out-Info "Sin Wi-Fi conectado (o Windows no deja leerlo sin permiso de ubicacion)."
        }
        # Doble NAT: el segundo salto es otra red privada
        if (Test-Cmd "tracert") {
            $tr = tracert -d -h 3 -w 400 1.1.1.1 2>$null
            $saltos = @()
            foreach ($l in $tr) { if ($l -match '^\s*(\d+)\s+.*?(\d+\.\d+\.\d+\.\d+)\s*$') { $saltos += [pscustomobject]@{ N = [int]$Matches[1]; Ip = $Matches[2] } } }
            if ($saltos.Count -gt 0) { Out-Info ("Traceroute: " + (($saltos | ForEach-Object { [string]$_.N + "=" + $_.Ip }) -join "  ")) }
            $s2 = $saltos | Where-Object { $_.N -eq 2 } | Select-Object -First 1
            if ($s2 -and (Test-Privada $s2.Ip) -and -not ($s2.Ip -match '^100\.')) {
                Add-Hallazgo 1 ("Doble NAT: el segundo salto (" + $s2.Ip + ") es otra red privada. Hay un PC o router extra entre este PC y el router.")
            }
        }
        # Historial de redes con nombre de punto de acceso de Windows (ultimos 7 dias)
        $raiz = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles"
        if (Test-Path $raiz) {
            foreach ($k in Get-ChildItem $raiz -ErrorAction SilentlyContinue) {
                $pr = Get-ItemProperty $k.PSPath -ErrorAction SilentlyContinue
                if (-not $pr -or -not $pr.ProfileName) { continue }
                $fecha = $null
                if ($pr.DateLastConnected -is [byte[]] -and $pr.DateLastConnected.Length -ge 16) {
                    $b = $pr.DateLastConnected
                    try {
                        $fecha = Get-Date -Year ([BitConverter]::ToUInt16($b, 0)) -Month ([BitConverter]::ToUInt16($b, 2)) -Day ([BitConverter]::ToUInt16($b, 6)) `
                            -Hour ([BitConverter]::ToUInt16($b, 8)) -Minute ([BitConverter]::ToUInt16($b, 10)) -Second 0
                    } catch {}
                }
                $reciente = ($fecha -eq $null -or $fecha -gt (Get-Date).AddDays(-7))
                if ($pr.ProfileName -match $patronHotspot -and $reciente) {
                    Add-Hallazgo 1 ("Se conecto hace poco a una red con nombre de punto de acceso de Windows: '" + $pr.ProfileName + "' (" + $(if ($fecha) { $fecha.ToString("yyyy-MM-dd HH:mm") } else { "fecha ?" }) + ").")
                }
            }
        }
    } catch {
        Out-Linea ("  Error en la prueba de red: " + $_.Exception.Message) "Yellow"
    }
} else {
    Out-Info "Solo en Windows."
}

# --------------------------------------------------------------------------
# 4. Rastros de Faker en este PC
# --------------------------------------------------------------------------
Out-Titulo "4. Rastros de Faker en este PC"
if ($script:EsWindows) {
    try {
        $carpetas = @()
        if ($env:APPDATA) { $carpetas += (Join-Path $env:APPDATA ".faker") }
        if ($env:USERPROFILE) { $carpetas += (Join-Path $env:USERPROFILE ".faker") }
        foreach ($c in $carpetas) {
            if (Test-Path $c) {
                $f = @(Get-ChildItem $c -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.Name + " (" + $_.LastWriteTime.ToString("yyyy-MM-dd HH:mm") + ")" })
                Add-Hallazgo 3 ("Carpeta de Faker: " + $c + "  ->  " + ($f -join ", "))
            }
        }
        # Proceso Faker abierto
        $jp = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -match '(?i)(net\.java\.faker|faker[-_ ]?[\d.]*\.(jar|exe))' -or $_.Name -match '(?i)^faker' })
        foreach ($p in $jp) { Add-Hallazgo 3 ("Faker abierto: PID " + $p.ProcessId + " " + $p.CommandLine) }
        # Driver WinDivert (Faker lo carga para desviar el trafico)
        $drv = @()
        try { $drv = @(Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '(?i)windivert' -or $_.PathName -match '(?i)windivert' }) } catch {}
        foreach ($d in $drv) {
            $txt = "Driver WinDivert (" + $d.Name + ", " + $d.State + "): " + $d.PathName
            if ($d.State -eq "Running") { Add-Hallazgo 2 ($txt + ". Lo usan Faker y otros programas que desvian trafico.") }
            else { Add-Hallazgo 1 ($txt + ". Instalado/usado en algun momento.") }
        }
        # Descargas y temporales
        $sitios = @()
        if ($env:USERPROFILE) { $sitios += @((Join-Path $env:USERPROFILE "Downloads"), (Join-Path $env:USERPROFILE "Desktop"), (Join-Path $env:USERPROFILE "Documents")) }
        if ($env:TEMP) { $sitios += $env:TEMP }
        foreach ($s in $sitios) {
            if (-not (Test-Path $s)) { continue }
            $hits = @(Get-ChildItem $s -Recurse -Depth 2 -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match '(?i)^(faker[-_ ]?[\d.]*\.(jar|exe|zip)|WinDivert64\.sys|win_redirect\.dll)$' })
            foreach ($h in $hits) { Add-Hallazgo 2 ("Archivo: " + $h.FullName + " (" + $h.LastWriteTime.ToString("yyyy-MM-dd HH:mm") + ")") }
        }
        # Prefetch (solo con administrador)
        $pf = Join-Path $env:WINDIR "Prefetch"
        try {
            $pfh = @(Get-ChildItem $pf -Filter "FAKER*.pf" -ErrorAction Stop)
            foreach ($h in $pfh) { Add-Hallazgo 2 ("Prefetch: " + $h.Name + " (ultima ejecucion " + $h.LastWriteTime.ToString("yyyy-MM-dd HH:mm") + ")") }
        } catch { Out-Info "Prefetch no legible (ejecuta como administrador para mirarlo)." }
        # Este PC compartiendo Internet (seria el PC del cheat)
        if (Test-Cmd "Get-NetIPAddress") {
            $ics = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -like "192.168.137.*" })
            foreach ($i in $ics) { Add-Hallazgo 1 ("Este PC tiene " + $i.IPAddress + " en '" + $i.InterfaceAlias + "': esta compartiendo su Internet (punto de acceso).") }
        }
    } catch {
        Out-Linea ("  Error buscando rastros: " + $_.Exception.Message) "Yellow"
    }
    if (-not ($script:Hallazgos | Where-Object { $_.Texto -match '^(Carpeta|Faker abierto|Driver|Archivo|Prefetch|Este PC)' })) {
        Out-Ok "Nada de Faker en este PC (normal: Faker corre en el OTRO PC)."
    }
} else {
    Out-Info "Solo en Windows."
}

# --------------------------------------------------------------------------
# Veredicto
# --------------------------------------------------------------------------
Out-Titulo "Veredicto"
$max = 0
foreach ($h in $script:Hallazgos) { if ($h.Nivel -gt $max) { $max = $h.Nivel } }
$fuertes = @($script:Hallazgos | Where-Object { $_.Nivel -ge 2 }).Count
$indicios = @($script:Hallazgos | Where-Object { $_.Nivel -eq 1 }).Count
if ($max -ge 3) {
    Out-Linea "  FAKER DETECTADO: hay un proxy desviando la conexion de Minecraft." "Red"
} elseif ($fuertes -ge 2 -or ($fuertes -ge 1 -and $indicios -ge 1)) {
    Out-Linea "  MUY SOSPECHOSO: el PC sale a Internet por otro PC y/o la conexion la contesta un proxy." "Magenta"
} elseif ($fuertes -ge 1 -or $indicios -ge 2) {
    Out-Linea "  SOSPECHOSO: revisa los hallazgos y pregunta por la red del jugador." "Yellow"
} else {
    Out-Linea "  Sin rastro de Faker." "Green"
}
if ($destinos.Count -eq 0) {
    Out-Linea "  OJO: no se midio ningun server. Repite con el jugador dentro del server." "Yellow"
}

if (-not $SinInforme -and $script:EsWindows) {
    try {
        $esc = [Environment]::GetFolderPath("Desktop")
        $ruta = Join-Path $esc ("AntiFaker_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".txt")
        $script:Lineas | Set-Content -Path $ruta -Encoding UTF8
        Out-Linea ("Informe guardado en " + $ruta) "White"
    } catch {}
}
