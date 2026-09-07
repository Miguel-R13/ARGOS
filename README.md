# ARGOS · AI-Augmented SOC Detection & Response Platform

> *XDR open source con IA local, construido desde cero sobre Wazuh. Cada regla nació de un ataque real ejecutado en laboratorio. Cada decisión de la IA fue supervisada, corregida y documentada: 91 correcciones · +20 escenarios de ataque sin cubrir identificados · TTPs de MITRE alucinados en producción · evidencia forense en riesgo por recomendación del LLM.*

---

## Qué es ARGOS

ARGOS (Augmented Response and Guidance Operations System) es un XDR de laboratorio construido como Trabajo Fin de Máster en Ciberseguridad (IMMUNE x Universidad Nebrija x Banco Santander) y como diferenciador técnico para roles SOC Analyst / Blue Team L1.

No es un Wazuh instalado con las reglas por defecto. Es un sistema de seis capas donde cada componente fue diseñado, implementado, atacado empíricamente y corregido por un analista con criterio SOC propio.

La tesis central: **la IA es la herramienta más potente disponible para un analista de seguridad, y la que más supervisión necesita.** ARGOS lo demuestra con 91 correcciones documentadas donde el criterio profesional cerró gaps que la IA no fue capaz de identificar sola.

---

## Arquitectura

Seis capas operativas sobre una red SOC LAN aislada:

```
                ┌──────────────────────────────────┐
                │      ARGOS · Wazuh Server        │
                │      192.168.234.10              │
                │                                  │
                │  OpenSearch + Dashboards         │
                │  Reglas Sigma propias            │
                │  Reglas XML propias              │
                │  Reglas YARA propias             │
                │  Suricata IDS/IPS                │
                │  SOAR Playbooks (Python)         │
                │  Triaje LLM daemon               │
                │  Integración TheHive daemon      │
                └──────────┬───────────────────────┘
                           │
              ┌────────────┴────────────┐
              │ SSH tunnel cifrado      │ API REST
              │ ED25519 key auth        │ HTTP :9000
       ┌──────▼──────┐          ┌───────▼──────────┐
       │ Host Windows│          │ ARGOS-TheHive     │
       │ Ollama      │          │ 192.168.234.50    │
       │ Mistral 7B  │          │                   │
       │ 127.0.0.1   │          │ TheHive 5.7.6     │
       └─────────────┘          │ Cassandra 4.1     │
                                │ Elasticsearch 7.x │
                                └───────────────────┘
                           │
          ┌────────────────┼────────────────┐
          │                │                │
┌─────────▼──────┐ ┌──────▼───────┐ ┌─────▼────────┐
│ Endpoint Linux │ │ Endpoint Win │ │    Kali      │
│ 192.168.234.30 │ │192.168.234.20│ │192.168.234.40│
│                │ │              │ │  (atacante)  │
│ auditd         │ │ Sysmon v15   │ └──────────────┘
│ auth.log       │ │ ScriptBlock  │
│ ufw.log        │ │ Security Log │
│ Wazuh Agent    │ │ Wazuh Agent  │
└────────────────┘ └──────────────┘
```

### Flujo de alerta extremo a extremo

```
Wazuh alerts.json
       │
       ▼
argos_triage_llm.py          ← daemon systemd en .10
  Mistral 7B via SSH tunnel
  9 campos de triaje
       │
       ├──► Telegram SOC Bot        ← notificación inmediata al analista
       │
       └──► argos_triage_cache.json ← caché indexado por alert_id
                   │
                   ▼
       argos_thehive_integration.py ← daemon systemd en .10
         monitoriza alerts.json
         nivel 13+ → caso automático
         triaje LLM adjunto como nota
                   │
                   ▼
           TheHive 5 · .50:9000
           caso documentado + veredicto del analista
```

---

## Stack

| Capa | Tecnología |
| --- | --- |
| SIEM / XDR | **Wazuh 4.9.2** + OpenSearch Dashboards |
| Detección por comportamiento | Reglas **Sigma propias** (.yml) compiladas a OpenSearch via `sigma-cli` |
| Detección nativa | Reglas **XML Wazuh propias** creadas desde cero con validación empírica |
| Detección por contenido | **Reglas YARA propias** · 24 reglas sobre la kill chain ESC01-ESC24 |
| Telemetría Linux | **auditd** (syscalls), auth.log, ufw.log |
| Telemetría Windows - procesos | **Sysmon v15** (SwiftOnSecurity config) |
| Telemetría Windows - scripts | **ScriptBlock Logging** (Event ID 4104) |
| Telemetría Windows - autenticación | **Security Event Log** (EID 4625, 4624, 4698, 5157...) |
| Detección de red | **Suricata IDS/IPS** · 27 reglas · 5 capas kill chain |
| SOAR | **Python** · 10 playbooks · contención activa + escalado humano · Telegram |
| Triaje IA | **Ollama** · Mistral 7B · 100% local · SSH tunnel cifrado · validado empíricamente |
| Gestión de incidentes | **TheHive 5.7.6** · Cassandra 4.1 · Elasticsearch 7.x · VM dedicada .50 |
| Módulo de phishing | **PhishGuard** (en desarrollo) |
| Framework de detección | **MITRE ATT&CK** |
| Framework de respuesta | **NIST** IR lifecycle |

---

## El problema que resuelve

Los SOC modernos se ahogan en alertas. El modelo clásico de L1 revisando cientos de eventos al día ya no escala. Pero el problema no es solo el volumen: es que la mayoría de entornos Wazuh se despliegan con las reglas por defecto, sin validar si realmente detectan lo que dicen detectar.

ARGOS parte de una premisa diferente: **ninguna regla de detección es válida hasta que un ataque real la dispara en laboratorio.**

El resultado es un XDR donde cada alerta tiene un origen trazable: sabes exactamente por qué dispara, qué ataque la genera, qué dijo la IA sobre esa alerta, y qué decisión tomó el analista cuando la IA no llegaba sola.

---

## Lo que diferencia a ARGOS

- **Detección original, no copiada.** Cada regla nace de un ataque real ejecutado en laboratorio. Los repositorios de referencia (SigmaHQ, Neo23x0/ANY.RUN/ReversingLabs, ET Open) se usan para identificar gaps, no para copiar lo que ya existe.
- **Ningún campo se asume.** El ataque se simula primero, se analiza la telemetría, y solo entonces se escribe la regla. Nunca al revés.
- **Human-in-the-loop documentado.** El analista no solo supervisa alertas: supervisa la lógica de detección, identifica sus gaps y aprueba las acciones de respuesta. El Capítulo 14 registra cada corrección técnica donde el criterio profesional superó a la herramienta.
- **Kill chain completa, no escenarios aislados.** 24 escenarios Sigma/XML (Linux ESC01-ESC10 + Windows ESC11-ESC24). 21 escenarios Suricata cubriendo las 5 capas de la kill chain de red. 10 playbooks SOAR cubriendo la kill chain completa de respuesta.
- **Evidencia de cada paso.** Cada escenario tiene capturas del ataque, la telemetría, el alerts.log y el dashboard. Nada sin validar.
- **Detección multicapa.** Comportamiento (Sigma/XML), contenido (YARA), red (Suricata IDS/IPS) y triaje IA (Ollama) como capas complementarias e independientes.
- **IDS + IPS.** Suricata opera en modo activo: 19 reglas alert para visibilidad y 8 reglas drop para bloqueo selectivo de vectores con certeza absoluta.
- **SOAR operativo.** 10 playbooks Python: 4 de contención activa (reverse shell, brute force SSH, brute force RDP, exfiltración) y 6 de escalado humano (movimiento lateral, desactivación de herramientas, persistencia, credential dumping, LOLBAS, beaconing C2).
- **Triaje LLM local validado empíricamente.** Pipeline completo Wazuh alerts.json → Ollama/Mistral 7B via SSH tunnel cifrado → caché JSON → Telegram SOC. 25 iteraciones de prompt engineering documentadas en 5 escenarios. 100% local, sin datos enviados a APIs externas.
- **Gestión de incidentes con TheHive.** Creación automática de casos para alertas nivel 13+, con el triaje LLM adjunto como nota estructurada. Cierra el loop del analista: detectar, triar, documentar y decidir en un flujo único y trazable.

---

## Las correcciones que la IA no hizo sola

Este es el núcleo argumentativo de ARGOS. No un XDR bonito. Una demostración empírica de dónde falla la IA cuando diseña detección de seguridad sin supervisión profesional. **91 correcciones documentadas en el Capítulo 14**, organizadas por bloque del sistema.

**El patrón que se repite en cada capa: la IA propone lo que suena razonable. El analista identifica lo que falla en producción.**

### Gaps cuantitativos: lo que la IA propuso vs. lo que el analista implementó

| Bloque | IA propuso | Analista implementó | Gap sin cubrir |
| --- | --- | --- | --- |
| Reglas YARA | 4 reglas | 24 reglas | 83% de vectores de contenido malicioso sin cobertura |
| Vectores C2 y beaconing Suricata | 3 vectores | 10 vectores | 70% de canales C2 documentados en TI 2024-2025 sin detección |
| Vectores movimiento lateral Suricata | 3 vectores | 6 vectores | WMI/RPC, Pass-the-Hash y port scan interno sin alerta de red |
| Reglas drop IPS Suricata | 2 drops | 8 drops | Reverse shell TCP, C2 HTTP, DNS tunneling activos mientras el analista lee la alerta |
| Reglas Mimikatz | 1 regla genérica | 3 reglas con respuestas distintas | Dominio completamente comprometido notificado igual que un script en disco |
| Playbooks SOAR | 5 playbooks | 10 playbooks + arquitectura rediseñada | Respuestas contradictorias sobre el mismo incidente |
| Vectores desactivación herramientas Windows | 2 vectores (Defender + Firewall) | 4 vectores | Agente Wazuh y Sysmon sin protección |
| Técnicas ofuscación PowerShell YARA | 2 técnicas | 5 técnicas | SecureString, GZip/Deflate, AMSI bypass sin cobertura |
| Vectores persistencia crontab YARA | 1 vector | 5 vectores | curl/wget pipe bash, netcat, python sin detección |

### Los fallos que habrían causado daño real

Más allá de los números, hay un conjunto de decisiones de la IA que, de haberse implementado sin corrección, habrían causado daño operativo directo. Estos son los más graves, ordenados por impacto.

---

**1. El LLM recomendó terminar mimikatz.exe en un playbook de escalado humano obligatorio.**

PB08 (Credential Dumping / LSASS) es escalado humano obligatorio por definición: cuando mimikatz ha volcado LSASS, el dominio entero está comprometido y L2 necesita el sistema intacto para análisis forense. El LLM aplicó el patrón de contención automática aprendido de PB01-PB04 y recomendó al L1 verificar que el proceso mimikatz.exe había sido terminado. Si un L1 hubiera ejecutado esa instrucción, habría destruido evidencia forense crítica antes de que L2 llegara al caso, eliminando cualquier posibilidad de reconstruir el alcance del compromiso. La corrección requirió un guardrail explícito con prohibición absoluta: `NUNCA digas que el SOAR actuó en PB08, NUNCA digas que el proceso fue terminado`. El fallo no era ambiguo ni sutil. El modelo lo repitió incluso tras la primera corrección, requiriendo una segunda iteración con lenguaje más restrictivo.

---

**2. La IA propuso exponer Ollama en 0.0.0.0:11434 con el firewall de Windows como única barrera.**

La propuesta era técnicamente funcional: Ollama escuchando en todas las interfaces, acceso restringido por regla de firewall a la IP .10. El analista rechazó esta arquitectura por una razón de fondo: en un entorno SOC, el firewall de Windows es exactamente el tipo de control que un atacante con foothold en la red desactiva primero (T1562.001, el mismo escenario que ARGOS simula en ESC19). Si el firewall caía, Ollama quedaba accesible desde cualquier máquina de la SOC LAN, exponiendo el modelo que procesa alertas reales con contexto de incidentes activos a inyección de prompts o exfiltración de datos de investigación. Un informe de Oligo Security de 2024 documentó miles de instancias Ollama expuestas en internet sin autenticación siendo usadas para minería de criptomonedas. La corrección fue Ollama en 127.0.0.1 exclusivamente, con acceso únicamente via tunnel SSH con autenticación ED25519, sin excepciones.

---

**3. La IA detectaba brute force SSH por blacklist de herramientas. El analista invirtió el problema.**

La propuesta era una regla específica para el banner de Hydra (`SSH-2.0-libssh_0.x`) y otra para Medusa (`SSH-2.0-MEDUSA_1.0`). El analista rechazó el enfoque por razón estructural, no técnica: una blacklist es incompleta por definición. Cualquier herramienta nueva, cualquier script personalizado, cualquier atacante que modifique su banner evade la detección sin esfuerzo. El enfoque correcto invierte el problema: en lugar de definir qué es malicioso (conjunto abierto e ilimitado), definir qué es legítimo (conjunto cerrado y conocido). El analista capturó el tráfico SSH real de la SOC LAN con tcpdump, identificó que el único cliente legítimo es OpenSSH, y construyó una regla de whitelist que alerta sobre cualquier banner que no sea OpenSSH. Un atacante que use una herramienta de brute force que no exista todavía dispara la alerta. Con la blacklist de la IA, no.

---

**4. El LLM alucinó un ID MITRE inexistente en producción, con una alerta real de LSASS.**

Durante la validación empírica con ataques reales del laboratorio, el pipeline procesó dos alertas consecutivas de la misma regla (102103, nivel 15, LSASS credential dumping) generadas por mimikatz.exe en el endpoint Windows. Primera alerta: T1003.001 correcto. Segunda alerta, mismo ataque, mismo sistema, treinta segundos después: T1033.001, que no existe en el framework MITRE ATT&CK. Si ese triaje hubiera ido a TheHive sin revisión humana, el caso quedaría indexado con un TTP inexistente. Las correlaciones retrospectivas con otras alertas del mismo TTP fallarían. El analista L2 que recibiera el caso partiría de contexto incorrecto. La gravedad no está en el error puntual: está en que el error es indistinguible de un resultado correcto a simple vista, porque T1033.001 tiene el formato correcto y parece plausible en contexto.

---

**5. Active Response de Wazuh no disparaba para alertas de auditd. El sistema parecía operativo.**

La IA propuso Active Response como mecanismo de ejecución para PB01 (Reverse Shell Linux). Durante la implementación empírica se descubrió que Active Response no dispara correctamente para alertas con `log_format:audit` en Wazuh 4.9.2. El fallo no lanza ningún error, no genera ninguna excepción, no produce ningún log de fallo visible. El playbook aparecía en el inventario como activo y configurado. En producción, una reverse shell en el endpoint Linux habría generado la alerta correctamente, el L1 habría recibido la notificación Telegram correctamente, y la contención automatizada simplemente no habría ocurrido. Detección sin respuesta, sin ninguna señal de que algo fallaba. La corrección fue rediseñar hacia el patrón de integration script que usan las integraciones oficiales de Wazuh.

---

**6. La IA protegió Defender y el Firewall. No contempló que el propio agente Wazuh es un objetivo.**

En ESC19 (Desactivación de herramientas de seguridad, T1562.001), la IA propuso cubrir únicamente la desactivación de Windows Defender (Event ID 5001) y Windows Firewall (Event ID 2003). El analista identificó el gap más crítico posible de T1562.001: si el atacante detiene el agente Wazuh, el endpoint queda completamente ciego para el SIEM. No evade una regla de detección. Elimina el canal completo por el que llegan todas las reglas. Desde ese momento, cualquier actividad posterior en el endpoint (movimiento lateral, credential dumping, exfiltración) ocurre en silencio total. La cobertura añadida (reglas 101902/101903/101905) detecta la parada del agente y dispara alerta de nivel crítico antes de que el endpoint desaparezca del dashboard.

---

**El analista L1 no va a desaparecer. Va a dejar de mirar logs para convertirse en quien valida, interroga y corrige a la IA. ARGOS documenta exactamente eso, con 91 correcciones y los registros de cada una.**

---

## Inventario de detección

### Bloque Linux · Endpoint 192.168.234.30 · Kill chain completa

| # | Escenario | TTP MITRE ATT&CK | Estado |
| --- | --- | --- | --- |
| ESC01 | Reconocimiento de red con Nmap | T1046 · Network Service Discovery | ✅ |
| ESC02 | Fuerza bruta SSH | T1110 · Brute Force | ✅ |
| ESC03 | Enumeración de usuarios | T1087.001 · Account Discovery | ✅ |
| ESC04 | Escalada de privilegios con sudo | T1548.003 · Sudo and Sudo Caching | ✅ |
| ESC05 | Reverse shell bash | T1059.004 · Unix Shell | ✅ |
| ESC06 | Cron job malicioso | T1053.003 · Scheduled Task: Cron | ✅ |
| ESC07 | Movimiento lateral SSH | T1021.004 · Remote Services: SSH | ✅ |
| ESC08 | Transferencia lateral SCP/SFTP | T1570 · Lateral Tool Transfer | ✅ |
| ESC09 | Desactivación de herramientas de seguridad | T1562.001 · Impair Defenses | ✅ |
| ESC10 | Exfiltración de datos via curl/wget | T1041 + T1105 | ✅ |

### Bloque Windows · Endpoint 192.168.234.20 · Kill chain completa

| # | Escenario | TTP MITRE ATT&CK | Estado |
| --- | --- | --- | --- |
| ESC11 | Reconocimiento de red con Nmap | T1046 · Network Service Discovery | ✅ |
| ESC12 | Fuerza bruta RDP | T1110 · Brute Force | ✅ |
| ESC13 | Enumeración de usuarios Windows | T1087.001 · Account Discovery | ✅ |
| ESC14 | Escalada de privilegios UAC bypass fodhelper | T1548.002 · Bypass UAC | ✅ |
| ESC15 | Reverse shell PowerShell | T1059.001 · PowerShell | ✅ |
| ESC16 | Persistencia via tareas programadas | T1053.005 · Scheduled Task | ✅ |
| ESC17 | Movimiento lateral SMB/psexec | T1021.002 · SMB/Windows Admin Shares | ✅ |
| ESC18 | Transferencia lateral via SMB | T1570 · Lateral Tool Transfer | ✅ |
| ESC19 | Desactivación Defender/Wazuh/Sysmon | T1562.001 · Impair Defenses | ✅ |
| ESC20 | Exfiltración via certutil/PowerShell LOLBAS | T1041 + T1105 | ✅ |
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
| YARA-09 | Script desactivación herramientas seguridad | ESC19 | Defense Evasion | T1562.001 | ✅ |
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
| SURICATA-ESC02 | SSH Brute Force banner no estándar | Acceso inicial | T1110.001 | alert+drop | ✅ |
| SURICATA-ESC03 | Reverse Shell TCP hacia zona atacantes interna | C2 | T1059.004 | alert+drop | ✅ |
| SURICATA-ESC03b | Reverse Shell TCP hacia IP externa | C2 | T1059.004 | alert | ✅ |
| SURICATA-ESC04 | HTTP Beaconing en SOC LAN | C2 | T1071.001 | alert+drop | ✅ |
| SURICATA-ESC05 | DNS Tunneling subdominio largo | C2 | T1071.004 | alert+drop | ✅ |
| SURICATA-ESC06 | ICMP Tunneling payload anómalo | C2 | T1095 | alert+drop | ✅ |
| SURICATA-ESC07 | Long Connection TCP beaconing persistente | C2 | T1571 | alert | ✅ |
| SURICATA-ESC08 | SSH hacia múltiples destinos internos | Movimiento lateral | T1021.004 | alert | ✅ |
| SURICATA-ESC09 | RDP hacia múltiples destinos internos | Movimiento lateral | T1021.001 | alert | ✅ |
| SURICATA-ESC09b | RDP Brute Force mismo destino | Movimiento lateral | T1110.001 | alert | ✅ |
| SURICATA-ESC10 | SMB anómalo entre endpoints | Movimiento lateral | T1021.002 | alert | ✅ |
| SURICATA-ESC11 | WMI RPC puerto 135 | Movimiento lateral | T1047 | alert | ✅ |
| SURICATA-ESC12 | Pass-the-Hash NTLMSSP SMB | Movimiento lateral | T1550.002 | alert+drop | ✅ |
| SURICATA-ESC13 | Port scan interno desde endpoint comprometido | Movimiento lateral | T1046 | alert | ✅ |
| SURICATA-ESC14 | Exfiltración por volumen de datos TCP | Exfiltración | T1048 | alert | ✅ |
| SURICATA-ESC15 | FTP saliente, protocolo inseguro | Exfiltración | T1048.003 | alert+drop | ✅ |
| SURICATA-ESC16 | SMB hacia exterior | Exfiltración | T1048 | alert+drop | ✅ |

### Bloque SOAR · Playbooks Python · Kill chain completa

| # | Escenario | Sensores | Tipo | Estado |
| --- | --- | --- | --- | --- |
| PB01 | Reverse Shell / C2 | ESC05/ESC15 + YARA-01/06 + SURICATA-ESC03 | Contención activa (ufw/netsh + kill) | ✅ |
| PB02 | Brute Force SSH | ESC02 + SURICATA-ESC02 | Contención activa (ufw) | ✅ |
| PB03 | Brute Force RDP | ESC12 + SURICATA-ESC09b | Contención activa (netsh) | ✅ |
| PB04 | Exfiltración de datos | ESC10/ESC20 + SURICATA-ESC14/15 | Contención activa (kill + ufw/netsh) | ✅ |
| PB05 | Movimiento lateral | ESC07/08/17/18 + SURICATA-ESC08/09/10/11 | Escalado humano | ✅ |
| PB06 | Desactivación herramientas seguridad | ESC09/19 + YARA-09 | Escalado humano | ✅ |
| PB07 | Persistencia | ESC06/16 + YARA-02/07 | Escalado humano | ✅ |
| PB08 | Credential Dumping / LSASS | ESC21/22 + YARA-13/14/15 | Escalado humano obligatorio | ✅ |
| PB09 | LOLBAS / Defense Evasion | ESC23/24 + YARA-16 al 24 | Escalado humano | ✅ |
| PB10 | Beaconing / C2 red | SURICATA-ESC04/05/06/07 | Escalado humano | ✅ |

### Triaje LLM · Pipeline Ollama local

| Componente | Detalle | Estado |
| --- | --- | --- |
| Modelo | Mistral 7B (inferencia CPU, 100% local) | ✅ |
| Canal | SSH tunnel ED25519 · .10:8888 → Windows:11434 | ✅ |
| Seguridad | OLLAMA_HOST=127.0.0.1, firewall Windows bloqueando puerto 11434, OpenSSH hardened | ✅ |
| Script | `llm/argos_triage_llm.py` · daemon tiempo real sobre alerts.json | ✅ |
| Caché | `argos_triage_cache.json` · indexado por alert_id · puente con TheHive | ✅ |
| Notificación | Telegram bot ARGOS_SOC_Bot | ✅ |
| Validación | 25 iteraciones en 5 escenarios · validación empírica con ataques reales | ✅ |
| Errores documentados | Alucinaciones MITRE, confusión de playbooks, degradación de prompt acumulado | ✅ |

### Integración TheHive · Gestión de incidentes

| Componente | Detalle | Estado |
| --- | --- | --- |
| Instancia | TheHive 5.7.6 · all-in-one single node · VM dedicada | ✅ |
| Backend | Cassandra 4.1 + Elasticsearch 7.x | ✅ |
| Acceso | http://192.168.234.50:9000 · SOC LAN VMnet1 | ✅ |
| Script | `thehive/argos_thehive_integration.py` · monitoriza alerts.json | ✅ |
| Umbral | Casos automáticos para alertas nivel 13+ · manuales para nivel 10-12 | ✅ |
| Triaje adjunto | 9 campos Mistral 7B como nota estructurada en cada caso | ✅ |
| Usuario servicio | argos-bot@argos.local · tipo Service · perfil analyst · sin privilegios admin | ✅ |
| Servicios systemd | `argos-triage-llm` + `argos-thehive` · activos en .10 | ✅ |

---

## Estado y roadmap

| Componente | Estado |
| --- | --- |
| Wazuh 4.9.2 + OpenSearch + agentes | ✅ Implementado |
| Sysmon v15 (SwiftOnSecurity) en endpoint Windows | ✅ Implementado |
| ScriptBlock Logging en endpoint Windows | ✅ Implementado |
| Reglas Sigma propias · 28 reglas (10 Linux + 18 Windows) | ✅ Completado |
| Reglas XML Wazuh propias · bloque Linux ESC01-ESC10 | ✅ Completado |
| Reglas XML Wazuh propias · bloque Windows ESC11-ESC24 | ✅ Completado |
| Pipeline YARA · FIM + Active Response + decoder + reglas XML | ✅ Implementado |
| Reglas YARA · 24 reglas completas (YARA-01 a YARA-24) | ✅ Completado |
| Suricata IDS/IPS · 27 reglas · 5 capas kill chain · 8 drops | ✅ Completado |
| Playbooks SOAR en Python · 10 playbooks PB01-PB10 | ✅ Completado |
| Notificaciones Telegram · canal ARGOS SOC Alerts | ✅ Completado |
| Triaje LLM local (Ollama + Mistral 7B) | ✅ Completado |
| Integración TheHive 5 · gestión de incidentes | ✅ Completado |
| Dashboard de supervisión humana | 🔨 En desarrollo |
| Integración PhishGuard | 🔨 En desarrollo |
| Evaluación cuantitativa (MTTD · MTTR · precisión LLM) | 📅 Pendiente |
| Release público completo | 📅 Q4 2026 |

---

## Infraestructura del laboratorio

| VM | IP | SO | RAM | Rol |
| --- | --- | --- | --- | --- |
| ARGOS-Wazuh | 192.168.234.10 | Ubuntu 22.04 | 8 GB | Wazuh 4.9.2 + OpenSearch + SOAR + LLM daemons |
| ARGOS-Windows | 192.168.234.20 | Windows 10 Pro | 4 GB | Endpoint Windows + Ollama/Mistral 7B |
| ARGOS-Linux | 192.168.234.30 | Ubuntu 22.04 | 2 GB | Endpoint Linux |
| ARGOS-Kali | 192.168.234.40 | Kali Linux | - | Atacante |
| ARGOS-TheHive | 192.168.234.50 | Ubuntu 22.04 | 8 GB | TheHive 5.7.6 + Cassandra 4.1 + Elasticsearch 7.x |

Red SOC LAN: 192.168.234.0/24 VMnet1 Host-only. Host: laptop i7 32 GB, VMware 17.6.4 + Docker.

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
│       ├── argos_pb01_integration.py
│       ├── argos_pb01_windows_integration.py
│       ├── argos_pb02_integration.py
│       ├── argos_pb03_integration.py
│       ├── argos_pb04_integration.py
│       ├── argos_pb04_windows_integration.py
│       ├── argos_pb05_integration.py
│       ├── argos_pb06_integration.py
│       ├── argos_pb07_integration.py
│       ├── argos_pb08_integration.py
│       ├── argos_pb09_integration.py
│       ├── argos_pb10_integration.py
│       └── argos-pb0*.service
├── llm/
│   ├── argos_triage_llm.py          # Daemon triaje tiempo real · alerts.json → Ollama → caché + Telegram
│   ├── argos_chat.py                # Herramienta desarrollo prompt interactivo
│   ├── argos_test_llm.py            # Test básico de inferencia
│   └── argos-ollama-tunnel.service  # Servicio systemd SSH tunnel
├── thehive/
│   ├── argos_thehive_integration.py # Monitoriza alerts.json · crea casos nivel 13+ con triaje LLM adjunto
│   ├── argos-thehive.service        # Servicio systemd integración TheHive
│   └── argos-triage-llm.service     # Servicio systemd daemon triaje LLM
├── dashboard/                       # Dashboard supervisión humana (en desarrollo)
├── docs/
│   └── architecture/                # Diagramas de arquitectura
└── README.md
```

---

## Requisitos

- Wazuh Server 4.9.2 + agente Linux o Windows
- OpenSearch + OpenSearch Dashboards
- Sysmon v15+ con configuración SwiftOnSecurity (endpoints Windows)
- Python 3.11+
- sigma-cli 3.0.3
- YARA 4.5.5
- Suricata 6.0.4+
- pywinrm (para playbooks Windows)
- Ollama con Mistral 7B (host con acceso SSH desde el servidor Wazuh)
- TheHive 5.7.6 + Cassandra 4.1 + Elasticsearch 7.x (VM dedicada recomendada, 8 GB RAM)

---

## Autor

**Miguel Reguero** · Blue Team / SOC Analyst
[LinkedIn](https://www.linkedin.com/in/miguel-reguero/) · [GitHub](https://github.com/Miguel-R13) · [Portfolio](https://miguel-r13.github.io)

Master en Ciberseguridad · IMMUNE x Universidad Nebrija x Banco Santander · Nota media 9,5/10
Top 5% TryHackMe · Autor de [PhishGuard](https://github.com/Miguel-R13/Phishguard)
