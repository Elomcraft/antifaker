# AntiFaker

Detector de **Faker** ([o1seth/faker](https://github.com/o1seth/faker)) para screenshares de Minecraft.

## Uso rápido

Con el jugador **dentro del server**, en el PC que enseña, abrir PowerShell (Win+X → Terminal) y pegar:

```powershell
irm https://raw.githubusercontent.com/Elomcraft/antifaker/main/AntiFaker.ps1 | iex
```

Si da error de TLS (Windows 10 antiguo), usar este, que también sirve desde Win+R o desde CMD:

```
powershell -ep bypass -c "[Net.ServicePointManager]::SecurityProtocol='Tls12'; irm https://raw.githubusercontent.com/Elomcraft/antifaker/main/AntiFaker.ps1 | iex"
```

Indicando el server a mano (si no lo detecta solo):

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/Elomcraft/antifaker/main/AntiFaker.ps1))) -Servidor play.tuserver.com
```

No hace falta administrador (con administrador además mira el Prefetch). Tarda entre 20 y 60 segundos. Al final da un veredicto y guarda un informe `AntiFaker_*.txt` en el escritorio.

**Sin internet o sin comandos:** descargar [AntiFaker.bat](https://github.com/Elomcraft/antifaker/raw/main/AntiFaker.bat) y [AntiFaker.ps1](https://github.com/Elomcraft/antifaker/raw/main/AntiFaker.ps1) en la misma carpeta y abrir el `.bat` con doble clic.

## Qué es Faker

Faker es un proxy "man in the middle". El jugador juega con cheats en un PC y le enseña otro PC limpio al staff. El PC limpio sale a Internet por el punto de acceso Wi-Fi del PC del cheat, y Faker desvía la conexión de Minecraft para que los dos clientes compartan la misma sesión. En el PC limpio no hay nada de Faker que encontrar, así que AntiFaker busca **lo que Faker le hace a la red** de ese PC.

## Qué comprueba

| # | Prueba | Peso |
|---|--------|------|
| 1 | **Cebo:** conecta al puerto del server en IPs que no existen en Internet (192.0.2.1, 198.51.100.1, 203.0.113.1, reservadas por el RFC 5737). Sin nada en medio no conecta nunca. Faker desvía *cualquier* IP en ese puerto a su proxy, así que conecta en pocos milisegundos. Antes lo prueba en un puerto de control: si el control también conecta, la red lo intercepta todo y la prueba no cuenta. | **Definitiva** |
| 2 | **Latencia:** la conexión TCP al server se compara con el ping (o un puerto cerrado) a la misma IP. Faker contesta la conexión desde el otro PC sin retraso: sale en 2-5 ms cuando el server real está a 30+ ms. | Fuerte |
| 3 | **Red:** puerta de enlace `192.168.137.x` (Conexión compartida de Windows), sufijo `mshome.net`, SSID por defecto de punto de acceso (`DESKTOP-XXXXXXX 1234`), MAC de la puerta de enlace administrada localmente, BSSID igual a la puerta de enlace, doble NAT e historial de redes de punto de acceso de los últimos 7 días. | Indicios |
| 4 | **Rastros en este PC** (por si enseñan el PC del cheat): `%APPDATA%\.faker`, proceso Faker, driver WinDivert, archivos `faker-*.jar/exe`, Prefetch y si el PC está compartiendo su Internet. | Definitiva / fuerte |

## Veredictos

- **FAKER DETECTADO**: el cebo conectó o hay archivos o proceso de Faker.
- **MUY SOSPECHOSO**: varias pruebas fuertes (latencia, red de PC compartido...).
- **SOSPECHOSO**: indicios sueltos; preguntar al jugador por su red.
- **Sin rastro de Faker**.

## Límites

- Basado en Faker 1.8 (agosto de 2026). Es de código abierto: si una versión futura limita el desvío a la IP del server, la prueba 1 dejará de saltar y quedarán la 2 y la 3.
- Programas como ExitLag, NoPing o Proxifier, configurados para desviar el puerto de Minecraft de todos los programas, podrían hacer saltar el cebo. Si el jugador usa uno, ciérralo y repite.
- Las pruebas de red son indicios: hay routers y redes de invitados con MAC locales y mucha gente con doble NAT.
- Windows 11 puede pedir permiso de ubicación para leer el Wi-Fi. Si no lo da, esa parte se salta.

## Seguridad

El script solo **lee**: no instala nada, no cambia la configuración ni envía datos a ningún sitio (las únicas conexiones son las pruebas al server, a las IPs cebo, a 1.1.1.1 para el traceroute y a la puerta de enlace). Es un solo archivo de texto: se puede leer entero antes de ejecutarlo.
