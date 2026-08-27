# ARGOS · AI-Augmented SOC Detection & Response Platform

> *"30+ correcciones documentadas donde la IA dejó gaps que un analista L1 tuvo que cerrar."*

XDR open source con supervisión humana del modelo, construido desde cero sobre Wazuh.

No es un Wazuh instalado con las reglas por defecto. Es un sistema donde cada regla de detección nació de un ataque real ejecutado en laboratorio, cada gap en repositorios de referencia fue identificado por mí (Miguel Reguero, Blue Team Analyst) y cubierto con detección original propia, y cada corrección técnica sobre las propuestas de la IA está documentada con criterio profesional SOC.

---

## Las correcciones que la IA no hizo sola

Este es el núcleo de ARGOS. No un XDR bonito. Una demostración empírica de dónde falla la IA cuando diseña detección de seguridad sin supervisión profesional.

**La IA es la herramienta más potente que he usado en ciberseguridad. Y la que más supervisión necesita.**

Si construyes un sistema de detección con Claude Pro sin un analista encima corrigiéndola constantemente, el resultado parece completo pero deja pasar los ataques reales. ARGOS lo demuestra empíricamente con más de 30 correcciones documentadas en el Capítulo 14 de la memoria del proyecto.

**El patrón que se repite en cada capa: la IA siempre propone el mínimo visible, nunca el mínimo necesario.**

La diferencia entre esos dos números es la superficie de ataque que el adversario puede explotar sin ser detectado. ARGOS lo cuantifica capa por capa:

- **YARA: 4 reglas propuestas vs. 24 implementadas.** La IA propuso cubrir 4 artefactos. El análisis sistemático de la kill chain completa determinó 24 escenarios con artefacto en disco, cada uno con su regla propia. Con 4 reglas, el 83% de los vectores de contenido malicioso habrían quedado sin cobertura: ninguna detección de LOLBAS, ninguna detección de ofuscación PowerShell, ninguna detección de credential dumping en disco.

- **Suricata C2 y beaconing: 3 vectores propuestos vs. 10 implementados.** La IA propuso reverse shell TCP, HTTP beaconing y DNS tunneling. El analista identificó 7 vectores adicionales documentados en campañas activas: ICMP tunneling, IRC (botnets), SMB como canal C2 (APT29, Lazarus), JA3/JA3S fingerprinting TLS, beaconing periódico, long connection y low-and-slow. Con 3 vectores, el 70% de los canales C2 reales documentados en threat intelligence de 2024-2025 habrían pasado sin detección.

- **Suricata movimiento lateral: 3 vectores propuestos vs. 6 implementados.** La IA propuso SSH lateral, RDP brute force y SMB anómalo. El analista añadió WMI/RPC (técnica principal de APTs en entornos Windows sin antivirus), Pass-the-Hash vía inspección de payload NTLMSSP, y port scan interno desde endpoint comprometido. Sin estos tres, un atacante que ya está dentro usando técnicas de living-off-the-land habría completado el movimiento lateral sin una sola alerta de red.

- **Suricata IPS: 2 drops propuestos vs. 8 implementados.** La IA propuso bloqueo activo solo para FTP y SMB exterior. El analista identificó 6 vectores adicionales con certeza suficiente para drop inmediato: reverse shell TCP confirmada hacia zona atacantes, HTTP en SOC LAN donde no debería existir, DNS tunneling, ICMP tunneling y Pass-the-Hash. Con 2 drops, un reverse shell activo, un canal C2 HTTP y un ataque de DNS tunneling habrían seguido funcionando mientras el analista procesaba las alertas.

- **Mimikatz: 1 regla propuesta vs. 3 implementadas con respuestas de incidente distintas.** La IA propuso una sola regla genérica. El analista identificó tres artefactos con respuestas radicalmente distintas: el script con comandos (intercepción posible antes de ejecutar), el log con credenciales volcadas (daño ocurrido, contención inmediata) y el minidump de LSASS (compromiso total: cambio de todas las credenciales del dominio sin excepción, incluyendo cuentas de servicio y administrador). Una regla genérica habría enviado al analista L1 la misma alerta para los tres casos, sin indicar que en uno de ellos el dominio entero está comprometido.

- **SOAR: 5 playbooks propuestos vs. 10 implementados, y arquitectura completamente rediseñada.** La IA propuso organizar los playbooks por regla de detección (un playbook por sensor) y usar un único script centralizado para los playbooks de escalado humano. El analista estableció que la arquitectura correcta es un playbook por escenario operativo (el analista L1 no distingue si la reverse shell la detectó Suricata, YARA o auditd: lo relevante es el escenario y la acción requerida) y scripts separados por plataforma (Linux vs. Windows) y por playbook (granularidad operativa, ciclos de vida independientes). Además la IA propuso Active Response de Wazuh como mecanismo de ejecución, y durante la implementación empírica se descubrió que no dispara correctamente para alertas de log_format:audit en Wazuh 4.9.2, requiriendo rediseño hacia el patrón de integration script que usan las integraciones oficiales de Wazuh.

**El analista L1 no va a desaparecer. Va a dejar de mirar logs para convertirse en quien valida, interroga y corrige a la IA. ARGOS documenta exactamente eso.**

---

## Pilar filosófico

**ARGOS rebate la tesis de que el analista L1 va a desaparecer por la IA.**

El Capítulo 14 de la memoria del proyecto demuestra empíricamente que si ARGOS se hubiese construido solo con IA habría dejado múltiples gaps críticos de cobertura sin cubrir. En cada escenario identifiqué correcciones de criterio SOC que la IA no fue capaz de proponer por sí sola: umbrales incorrectos, vectores de ataque ignorados, telemetría mal clasificada, exclusiones necesarias no contempladas, cobertura YARA insuficiente, arquitectura de detección de red incompleta, arquitectura SOAR mal diseñada.

La IA procesa. El analista decide. Y la diferencia entre los dos es exactamente lo que ARGOS documenta.

---

## Lo que diferencia a ARGOS

- **Detección original, no copiada.** Cada regla de detección nace de un ataque real ejecutado en laboratorio. Los repositorios de referencia (SigmaHQ para comportamiento, Neo23x0/ANY.RUN/ReversingLabs para contenido YARA, ET Open para red) se usan para identificar gaps, no para copiar lo que ya existe.
- **Ningún campo se asume.** El ataque se simula primero, se analiza la telemetría, y solo entonces se escribe la regla. Nunca al revés.
- **Human-in-the-loop documentado.** El analista no solo supervisa alertas: supervisa la lógica de detección, identifica sus gaps y aprueba las acciones de respuesta. El Capítulo 14 registra cada corrección técnica donde el criterio profesional superó a la herramienta.
- **Kill chain completa, no escenarios aislados.** 24 escenarios Sigma/XML en dos bloques: Linux (ESC01-ESC10) y Windows (ESC11-ESC24). 21 escenarios Suricata cubriendo las 5 capas de la kill chain de red. 10 playbooks SOAR cubriendo la kill chain completa de respuesta.
- **Evidencia de cada paso.** Cada escenario tiene capturas del ataque, la telemetría, el alerts.log y el dashboard. Nada sin validar.
- **Detección multicapa.** Comportamiento (Sigma/XML), contenido (YARA), red (Suricata IDS/IPS) y triaje IA (Ollama) como capas complementarias e independientes.
- **IDS + IPS.** Suricata opera en modo activo: 19 reglas alert para visibilidad y 8 reglas drop para bloqueo selectivo de vectores con certeza absoluta.
- **SOAR operativo.** 10 playbooks Python cubriendo la kill chain completa: 4 de contencion activa (reverse shell, brute force SSH, brute force RDP, exfiltracion) y 6 de escalado humano (movimiento lateral, desactivacion de herramientas, persistencia, credential dumping, LOLBAS, beaconing C2).

---

## El problema que resuelve

Los SOC modernos se ahogan en alertas. El modelo clásico de L1 revisando cientos de eventos al día ya no escala. Pero el problema no es solo el volumen: es que la mayoría de entornos Wazuh se despliegan con las reglas por defecto, sin validar si realmente detectan lo que dicen detectar.

ARGOS parte de una premisa diferente: **ninguna regla de detección es válida hasta que un ataque real la dispara en laboratorio**.

El resultado es un XDR open source donde cada alerta tiene un origen trazable: sabes exactamente por qué dispara, qué ataque la genera y qué decisión tomó el analista cuando la IA no llegaba sola.

---

## Arquitectura

```
                ┌─────────────────────────────┐
                │     ARGOS · Wazuh Server    │
                │     192.168.234.10          │
                │                             │
                │  OpenSearch + Dashboards    │
                │  Reglas Sigma propias       │
                │  Reglas XML propias         │
                │  Reglas YARA propias        │
                │  Suricata IDS/IPS           │
                │  SOAR Playbooks (Python)    │
                │  Ollama LLM local           │
                └──────────┬──────────────────┘
                           │
          ┌────────────────┼────────────────┐
          │                │                │
┌─────────▼──────┐ ┌──────▼───────┐ ┌─────▼────────┐
│ Endpoint Linux │ │ Endpoint Win │ │    Kali      │
│ 192.168.234.30 │ │ 192.168.234.20│ │ 192.168.234.40│
│                │ │              │ │  (atacante)  │
│ auditd         │ │ Sysmon v15   │ └──────────────┘
│ auth.log       │ │ ScriptBlock  │
│ ufw.log        │ │ Security Log │
│ Wazuh Agent    │ │ Wazuh Agent  │
└────────────────┘ └──────────────┘
```

---

## Stack

| Capa | Tecnologia |
| --- | --- |
| SIEM / XDR | **Wazuh 4.9.2** + OpenSearch Dashboards |
| Deteccion por comportamiento | Reglas **Sigma propias** (.yml) compiladas a OpenSearch via `sigma-cli` |
| Deteccion nativa | Reglas **XML Wazuh propias** creadas desde cero con validacion empirica |
| Deteccion por contenido | **Reglas YARA propias** · 24 reglas sobre la kill chain ESC01-ESC24 |
| Telemetria Linux | **auditd** (syscalls), auth.log, ufw.log |
| Telemetria Windows - procesos | **Sysmon v15** (SwiftOnSecurity config) |
| Telemetria Windows - scripts | **ScriptBlock Logging** (Event ID 4104) |
| Telemetria Windows - autenticacion | **Security Event Log** (EID 4625, 4624, 4698, 5157...) |
| Deteccion de red | **Suricata IDS/IPS** · 27 reglas · 5 capas kill chain |
| SOAR | **Python** · 10 playbooks · contencion activa + escalado humano · Telegram |
| Triaje IA | **Ollama** · Mistral 7B / LLaMA 3 8B, 100% local (en desarrollo) |
| Modulo de phishing | **PhishGuard** (en desarrollo) |
| Framework de deteccion | **MITRE ATT&CK** |
| Framework de respuesta | **NIST** IR lifecycle |

---

## Inventario de deteccion

### Bloque Linux · Endpoint 192.168.234.30 · Kill chain completa

| # | Escenario | TTP MITRE ATT&CK | Estado |
| --- | --- | --- | --- |
| ESC01 | Reconocimiento de red con Nmap | T1046 · Network Service Discovery | ✅ |
| ESC02 | Fuerza bruta SSH | T1110 · Brute Force | ✅ |
| ESC03 | Enumeracion de usuarios | T1087.001 · Account Discovery | ✅ |
| ESC04 | Escalada de privilegios con sudo | T1548.003 · Sudo and Sudo Caching | ✅ |
| ESC05 | Reverse shell bash | T1059.004 · Unix Shell | ✅ |
| ESC06 | Cron job malicioso | T1053.003 · Scheduled Task: Cron | ✅ |
| ESC07 | Movimiento lateral SSH | T1021.004 · Remote Services: SSH | ✅ |
| ESC08 | Transferencia lateral SCP/SFTP | T1570 · Lateral Tool Transfer | ✅ |
| ESC09 | Desactivacion de herramientas de seguridad | T1562.001 · Impair Defenses | ✅ |
| ESC10 | Exfiltracion de datos via curl/wget | T1041 + T1105 | ✅ |

### Bloque Windows · Endpoint 192.168.234.20 · Kill chain completa

| # | Escenario | TTP MITRE ATT&CK | Estado |
| --- | --- | --- | --- |
| ESC11 | Reconocimiento de red con Nmap | T1046 · Network Service Discovery | ✅ |
| ESC12 | Fuerza bruta RDP | T1110 · Brute Force | ✅ |
| ESC13 | Enumeracion de usuarios Windows | T1087.001 · Account Discovery | ✅ |
| ESC14 | Escalada de privilegios UAC bypass fodhelper | T1548.002 · Bypass UAC | ✅ |
| ESC15 | Reverse shell PowerShell | T1059.001 · PowerShell | ✅ |
| ESC16 | Persistencia via tareas programadas | T1053.005 · Scheduled Task | ✅ |
| ESC17 | Movimiento lateral SMB/psexec | T1021.002 · SMB/Windows Admin Shares | ✅ |
| ESC18 | Transferencia lateral via SMB | T1570 · Lateral Tool Transfer | ✅ |
| ESC19 | Desactivacion Defender/Wazuh/Sysmon | T1562.001 · Impair Defenses | ✅ |
| ESC20 | Exfiltracion via certutil/PowerShell LOLBAS | T1041 + T1105 | ✅ |
| ESC21 | Credential dumping LSASS/SAM | T1003.001 + T1003.002 | ✅ |
| ESC22 | Pass the Hash | T1550.002 · Pass the Hash | ✅ |
| ESC23 | LOLBAS: regsvr32, mshta, certutil, bitsadmin, wmic | T1218 · System Binary Proxy Execution | ✅ |
| ESC24 | PowerShell ofuscado EncodedCommand | T1027 · Obfuscated Files or Information | ✅ |

### Bloque YARA · Linux + Windows

| # | Regla YARA | Escenario | Fase Kill Chain | MITRE | Estado |
| --- | --- | --- | --- | --- | --- |
| YARA-01 | Bash reverse shell script en disco | ESC05 | Execution | T1059.004 | ✅ |
| YARA-02 | Bash reverse shell en crontab | ESC06 | Persistence | T1053.003 | ✅ |
| YARA-03 | Ingress tool transfer ELF + C2 frameworks | ESC10 | C2 | T1105 | ✅ |
| YARA-04 | Reverse shell Python y Perl | ESC10 | Execution | T1059.006 | ✅ |
| YARA-05 | Webshell PHP y Python | ESC10/ESC08 | Persistence | T1505.003 | ✅ |
| YARA-06 | PowerShell reverse shell TCPClient | ESC15 | Execution | T1059.001 | ✅ |
| YARA-07 | Script PowerShell schtasks persistencia | ESC16 | Persistence | T1053.005 | ✅ |
| YARA-08 | Herramienta ofensiva depositada via SMB | ESC17/ESC18 | Lateral Movement | T1570 | ✅ |
| YARA-09 | Script desactivacion herramientas seguridad | ESC19 | Defense Evasion | T1562.001 | ✅ |
| YARA-10 | Archivo Base64 generado por certutil -encode | ESC20 | Exfiltration | T1041 | ✅ |
| YARA-11 | Script PowerShell FromBase64String decoder | ESC20 | Defense Evasion | T1027 | ✅ |
| YARA-12 | Script batch certutil -decode | ESC20 | Defense Evasion | T1027 | ✅ |
| YARA-13 | Comandos mimikatz en scripts | ESC21/ESC22 | Credential Access | T1003.001 | ✅ |
| YARA-14 | Archivo log generado por mimikatz | ESC21/ESC22 | Credential Access | T1003.001 | ✅ |
| YARA-15 | LSASS minidump | ESC21/ESC22 | Credential Access | T1003.001 | ✅ |
| YARA-16 | LOLBAS certutil con URL | ESC23 | C2/Defense Evasion | T1105/T1218 | ✅ |
| YARA-17 | LOLBAS mshta/wscript/cscript con URL | ESC23 | Defense Evasion | T1218 | ✅ |
| YARA-18 | LOLBAS regsvr32/rundll32 con URL | ESC23 | Defense Evasion | T1218 | ✅ |
| YARA-19 | LOLBAS bitsadmin/msiexec/wmic con URL | ESC23 | Defense Evasion | T1218 | ✅ |
| YARA-20 | PowerShell EncodedCommand ofuscado | ESC24 | Defense Evasion | T1027.010 | ✅ |
| YARA-21 | PowerShell SecureString obfuscation | ESC24 | Defense Evasion | T1027.010 | ✅ |
| YARA-22 | PowerShell GZip/Deflate compression | ESC24 | Defense Evasion | T1027.010 | ✅ |
| YARA-23 | PowerShell AMSI bypass | ESC24 | Defense Evasion | T1562.001 | ✅ |
| YARA-24 | PowerShell string manipulation obfuscation | ESC24 | Defense Evasion | T1027.010 | ✅ |

### Bloque Suricata · Red 192.168.234.0/24 · 5 capas kill chain

| # | Escenario | Capa | TTP MITRE ATT&CK | Modo | Estado |
| --- | --- | --- | --- | --- | --- |
| SURICATA-ESC01 | TCP SYN Port Scan nmap invariant win:1024 | Reconocimiento | T1046 | alert | ✅ |
| SURICATA-ESC01b | Generic Scanner Threshold | Reconocimiento | T1046 | alert | ✅ |
| SURICATA-ESC02 | SSH Brute Force banner no estandar | Acceso inicial | T1110.001 | alert+drop | ✅ |
| SURICATA-ESC03 | Reverse Shell TCP hacia zona atacantes interna | C2 | T1059.004 | alert+drop | ✅ |
| SURICATA-ESC03b | Reverse Shell TCP hacia IP externa | C2 | T1059.004 | alert | ✅ |
| SURICATA-ESC04 | HTTP Beaconing en SOC LAN | C2 | T1071.001 | alert+drop | ✅ |
| SURICATA-ESC05 | DNS Tunneling subdominio largo | C2 | T1071.004 | alert+drop | ✅ |
| SURICATA-ESC06 | ICMP Tunneling payload anomalo | C2 | T1095 | alert+drop | ✅ |
| SURICATA-ESC07 | Long Connection TCP beaconing persistente | C2 | T1571 | alert | ✅ |
| SURICATA-ESC08 | SSH hacia multiples destinos internos | Movimiento lateral | T1021.004 | alert | ✅ |
| SURICATA-ESC09 | RDP hacia multiples destinos internos | Movimiento lateral | T1021.001 | alert | ✅ |
| SURICATA-ESC09b | RDP Brute Force mismo destino | Movimiento lateral | T1110.001 | alert | ✅ |
| SURICATA-ESC10 | SMB anomalo entre endpoints | Movimiento lateral | T1021.002 | alert | ✅ |
| SURICATA-ESC11 | WMI RPC puerto 135 | Movimiento lateral | T1047 | alert | ✅ |
| SURICATA-ESC12 | Pass-the-Hash NTLMSSP SMB | Movimiento lateral | T1550.002 | alert+drop | ✅ |
| SURICATA-ESC13 | Port scan interno desde endpoint comprometido | Movimiento lateral | T1046 | alert | ✅ |
| SURICATA-ESC14 | Exfiltracion por volumen de datos TCP | Exfiltracion | T1048 | alert | ✅ |
| SURICATA-ESC15 | FTP saliente, protocolo inseguro | Exfiltracion | T1048.003 | alert+drop | ✅ |
| SURICATA-ESC16 | SMB hacia exterior | Exfiltracion | T1048 | alert+drop | ✅ |

### Bloque SOAR · Playbooks Python · Kill chain completa

| # | Escenario | Sensores | Tipo | Estado |
| --- | --- | --- | --- | --- |
| PB01 | Reverse Shell / C2 | ESC05/ESC15 + YARA-01/06 + SURICATA-ESC03 | Contencion activa (ufw/netsh + kill) | ✅ |
| PB02 | Brute Force SSH | ESC02 + SURICATA-ESC02 | Contencion activa (ufw) | ✅ |
| PB03 | Brute Force RDP | ESC12 + SURICATA-ESC09b | Contencion activa (netsh) | ✅ |
| PB04 | Exfiltracion de datos | ESC10/ESC20 + SURICATA-ESC14/15 | Contencion activa (kill + ufw/netsh) | ✅ |
| PB05 | Movimiento lateral | ESC07/08/17/18 + SURICATA-ESC08/09/10/11 | Escalado humano | ✅ |
| PB06 | Desactivacion herramientas seguridad | ESC09/19 + YARA-09 | Escalado humano | ✅ |
| PB07 | Persistencia | ESC06/16 + YARA-02/07 | Escalado humano | ✅ |
| PB08 | Credential Dumping / LSASS | ESC21/22 + YARA-13/14/15 | Escalado humano obligatorio | ✅ |
| PB09 | LOLBAS / Defense Evasion | ESC23/24 + YARA-16 al 24 | Escalado humano | ✅ |
| PB10 | Beaconing / C2 red | SURICATA-ESC04/05/06/07 | Escalado humano | ✅ |

---

## Estado y roadmap

| Componente | Estado |
| --- | --- |
| Wazuh 4.9.2 + OpenSearch + agentes | ✅ Implementado |
| Sysmon v15 (SwiftOnSecurity) en endpoint Windows | ✅ Implementado |
| ScriptBlock Logging en endpoint Windows | ✅ Implementado |
| Reglas Sigma propias · 28 reglas (10 Linux + 18 Windows) | ✅ Implementado |
| Reglas XML Wazuh propias · bloque Linux ESC01-ESC10 | ✅ Completado |
| Reglas XML Wazuh propias · bloque Windows ESC11-ESC24 | ✅ Completado |
| Pipeline YARA · FIM + Active Response + decoder + reglas XML | ✅ Implementado |
| Reglas YARA · 24 reglas completas (YARA-01 a YARA-24) | ✅ Completado |
| Suricata IDS/IPS · 27 reglas · 5 capas kill chain · 8 drops | ✅ Completado |
| Playbooks SOAR en Python · 10 playbooks PB01-PB10 | ✅ Completado |
| Notificaciones Telegram · canal ARGOS SOC Alerts | ✅ Completado |
| Triaje con LLM local (Ollama) | 🔨 En desarrollo |
| Dashboard de supervision humana | 🔨 En desarrollo |
| Integracion PhishGuard | 🔨 En desarrollo |
| Evaluacion cuantitativa (MTTD · MTTR · precision LLM) | 📅 Pendiente |
| Release publico completo | 📅 Q4 2026 |

---

## Estructura del repositorio

```
ARGOS/
├── detection/
│   ├── sigma/                  # Reglas Sigma propias (.yml) · Linux + Windows
│   ├── wazuh/                  # Reglas XML Wazuh propias · Linux + Windows
│   │   ├── active-response/    # Scripts Active Response YARA
│   │   │   ├── argos_yara_scan.py      # Script AR Linux
│   │   │   └── argos_yara_scan_win.py  # Script AR Windows
│   │   ├── argos_yara_decoder.xml
│   │   ├── argos_yara_rules.xml        # Reglas 103000-103024
│   │   └── argos_suricata_rules.xml    # Reglas 110001-110021
│   ├── suricata/               # Reglas Suricata propias · 27 reglas · 5 capas
│   │   └── argos.rules         # 19 alert + 8 drop · IDS/IPS
│   └── yara/
│       ├── linux/              # 5 reglas YARA bloque Linux (YARA-01 a YARA-05)
│       └── windows/            # 19 reglas YARA bloque Windows (YARA-06 a YARA-24)
├── soar/
│   └── playbooks/              # 10 playbooks SOAR Python + servicios systemd
│       ├── argos_pb01_integration.py         # Reverse Shell Linux
│       ├── argos_pb01_windows_integration.py # Reverse Shell Windows
│       ├── argos_pb02_integration.py         # Brute Force SSH
│       ├── argos_pb03_integration.py         # Brute Force RDP
│       ├── argos_pb04_integration.py         # Exfiltracion Linux
│       ├── argos_pb04_windows_integration.py # Exfiltracion Windows
│       ├── argos_pb05_integration.py         # Movimiento lateral
│       ├── argos_pb06_integration.py         # Desactivacion herramientas
│       ├── argos_pb07_integration.py         # Persistencia
│       ├── argos_pb08_integration.py         # Credential Dumping / LSASS
│       ├── argos_pb09_integration.py         # LOLBAS / Defense Evasion
│       ├── argos_pb10_integration.py         # Beaconing / C2 red
│       └── argos-pb0*.service                # Servicios systemd
├── llm/                        # Pipeline triaje LLM Ollama (en desarrollo)
├── dashboard/                  # Dashboard de supervision humana (en desarrollo)
├── docs/
│   └── architecture/           # Diagramas de arquitectura
└── README.md
```

---

## Requisitos

- Wazuh Server 4.9.2 + agente Linux o Windows
- OpenSearch + OpenSearch Dashboards
- Sysmon v15+ con configuracion SwiftOnSecurity (endpoints Windows)
- Python 3.11+
- sigma-cli 3.0.3
- YARA 4.5.5
- Suricata 6.0.4+
- pywinrm (para playbooks Windows)
- Ollama con Mistral 7B o LLaMA 3 8B *(en desarrollo)*

---

## Autor

**Miguel Reguero** · Blue Team / SOC Analyst
[LinkedIn](https://www.linkedin.com/in/miguel-reguero/) · [GitHub](https://github.com/Miguel-R13) · [Portfolio](https://miguel-r13.github.io)

Master en Ciberseguridad · IMMUNE x Universidad Nebrija x Banco Santander · Nota media 9,5/10
Top 5% TryHackMe · Autor de [PhishGuard](https://github.com/Miguel-R13/Phishguard)
