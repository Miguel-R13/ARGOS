# ARGOS · AI-Augmented SOC Detection & Response Platform

> *"La IA propone. El analista decide. ARGOS documenta por qué importa la diferencia."*

XDR open source con supervisión humana del modelo, construido desde cero sobre Wazuh.

No es un Wazuh instalado con las reglas por defecto. Es un sistema donde cada regla de detección nació de un ataque real ejecutado en laboratorio, cada gap en herramientas de referencia como SigmaHQ fue identificado por mí (Miguel Reguero, Blue Team Analyst) y cubierto con detección original propia, y cada corrección técnica sobre las propuestas de la IA está documentada con criterio profesional SOC.

---

## Pilar filosófico

**ARGOS rebate la tesis de que el analista L1 va a desaparecer por la IA.**

El Capítulo 14 de la memoria del proyecto demuestra empíricamente que si ARGOS se hubiese construido solo con IA habría dejado múltiples gaps críticos de cobertura sin cubrir. En cada escenario identifiqué correcciones de criterio SOC que la IA no fue capaz de proponer por sí sola: umbrales incorrectos, vectores de ataque ignorados, telemetría mal clasificada, exclusiones necesarias no contempladas, cobertura YARA insuficiente...

La IA es una herramienta de asistencia. El criterio profesional del analista es el que diferencia un sistema de detección robusto de uno que parece completo pero deja pasar los ataques reales.

---

## Lo que diferencia a ARGOS

- **Detección original, no heredada.** Se parte de SigmaHQ para identificar lo que falta, no para copiar lo que existe. Cada regla Sigma y XML se construye desde cero con keywords validados empíricamente sobre telemetría real.
- **Ningún campo se asume.** El ataque se simula primero, se analiza la telemetría, y solo entonces se escribe la regla. Nunca al revés.
- **Human-in-the-loop documentado.** El analista no solo supervisa alertas: supervisa la lógica de detección, identifica sus gaps y aprueba las acciones de respuesta. El Capítulo 14 de la memoria del proyecto registra cada corrección técnica que el criterio profesional hace sobre la herramienta.
- **Kill chain completa, no escenarios aislados.** 24 escenarios organizados en dos bloques de kill chain real: Linux (ESC01-ESC10) y Windows (ESC11-ESC24), desde el reconocimiento hasta la exfiltración y el credential dumping.
- **Evidencia de cada paso.** Cada escenario tiene capturas del ataque, la telemetría, el alerts.log y el dashboard. No hay nada que no esté validado.
- **Detección multicapa.** Comportamiento (Sigma/XML), contenido (YARA), red (Suricata) y triaje IA (Ollama) como capas complementarias e independientes.

---

## El problema que resuelve

Los SOC modernos se ahogan en alertas. El modelo clásico de L1 revisando cientos de eventos al día ya no escala. Pero el problema no es solo el volumen: es que la mayoría de entornos Wazuh se despliegan con las reglas por defecto, sin validar si realmente detectan lo que dicen detectar.

ARGOS parte de una premisa diferente: **ninguna regla de detección es válida hasta que un ataque real la dispara en laboratorio**.

Esto cambia todo el proceso. En lugar de copiar reglas de SigmaHQ y asumir que funcionan, ARGOS usa SigmaHQ como referencia para identificar los gaps, y construye detección original que cubre lo que las herramientas estándar no cubren. Cada escenario tiene su ataque simulado, su telemetría analizada, sus keywords validados empíricamente y su evidencia documentada.

El resultado es un XDR open source donde cada alerta tiene un origen trazable: sabes exactamente por qué dispara, qué ataque la genera y qué decisión tomó el analista cuando la IA no llegaba sola.

---

## Qué hace ARGOS que otros no hacen

**Detección propia, no heredada.** Las reglas Sigma y XML de ARGOS se construyen desde cero partiendo del comportamiento invariante del ataque, no de firmas de comandos que un atacante puede evadir cambiando un argumento. Cada campo de detección se confirma sobre telemetría real antes de escribirse.

**Gaps documentados con criterio profesional.** Cuando SigmaHQ filtra por LogonType 10 y los ataques reales de brute force RDP generan LogonType 3, ARGOS lo detecta y lo corrige. Cuando la IA propone un umbral de correlación sin considerar las diferencias entre Windows Firewall y UFW, el analista lo ajusta empíricamente. Todo queda registrado en el Capítulo 14 de la memoria del proyecto.

**Cobertura de kill chain completa.** No escenarios aislados: dos kill chains completas documentadas, una sobre endpoint Linux (ESC01-ESC10) y otra sobre endpoint Windows (ESC11-ESC24), siguiendo la secuencia real de un atacante desde el reconocimiento hasta la exfiltración.

**YARA orientado a artefactos reales de la kill chain.** Las 11 reglas YARA de ARGOS no son firmas genéricas de malware: cada una detecta exactamente el artefacto que los escenarios ESC01-ESC24 depositan en los endpoints. La cobertura se determinó mediante análisis sistemático de los 24 escenarios para identificar cuáles generan archivos en disco susceptibles de análisis de contenido.

**Human-in-the-loop como principio de diseño.** El analista no solo supervisa las alertas. Supervisa la lógica de detección, corrige sus gaps y aprueba las acciones de respuesta automatizada. La IA es una herramienta, no el centro del sistema.

**Telemetría multicapa en Windows.** Sysmon con configuración SwiftOnSecurity para procesos, red y registro. ScriptBlock Logging (EID 4104) para contenido de scripts PowerShell post-deobfuscación, invariante ante cualquier técnica de ofuscación. Security Event Log para autenticación y auditoría de objetos. Tres fuentes complementarias que juntas cierran los gaps que cada una deja por separado.

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

| Capa | Tecnología |
| --- | --- |
| SIEM / XDR | **Wazuh 4.9.2** + OpenSearch Dashboards |
| Detección por comportamiento | Reglas **Sigma propias** (.yml) compiladas a OpenSearch via `sigma-cli` |
| Detección nativa | Reglas **XML Wazuh propias** creadas desde cero con validación empírica |
| Detección por contenido | **Reglas YARA propias** · 11 reglas sobre la kill chain ESC01-ESC24 🔨 |
| Telemetría Linux | **auditd** (syscalls), auth.log, ufw.log |
| Telemetría Windows - procesos | **Sysmon v15** (SwiftOnSecurity config) |
| Telemetría Windows - scripts | **ScriptBlock Logging** (Event ID 4104) |
| Telemetría Windows - autenticación | **Security Event Log** (EID 4625, 4624, 4698, 5157...) |
| Detección de red | **Suricata** IDS/IPS 🔨 |
| Triaje IA | **Ollama** · Mistral 7B / LLaMA 3 8B, 100% local 🔨 |
| Automatización | **Python** · Playbooks SOAR 🔨 |
| Alertas | **Telegram** 🔨 |
| Módulo de phishing | **PhishGuard** 🔨 |
| Framework de detección | **MITRE ATT&CK** |
| Framework de respuesta | **NIST** IR lifecycle |

---

## Proceso de validación · Los 9 puntos de cada escenario Sigma/XML

Ninguna regla Sigma/XML de ARGOS existe sin pasar por estos 9 puntos. No hay excepciones.

**1. Contexto de la amenaza**
Qué hace el atacante, qué posición ocupa en la kill chain, qué valor tiene para el adversario.

**2. Gap en herramientas nativas y SigmaHQ**
Qué detecta Wazuh por defecto, qué tiene SigmaHQ, qué queda sin cubrir y por qué importa ese gap. Este paso es fundamental y no es opcional: antes de escribir cualquier regla se revisa el repositorio SigmaHQ clonado localmente. ARGOS no crea reglas donde ya existe cobertura suficiente; solo construye detección original donde hay un gap real que las herramientas existentes no cubren.

**3. Decisiones de diseño, telemetría y obtención de keywords empíricos**
Simulación exploratoria previa: el ataque se ejecuta en laboratorio y se analiza la telemetría real. Ningún campo se asume. Los keywords invariantes son los que aparecen en el log real, no los que dice la documentación.

**4. Qué consigue ARGOS**
Qué cobertura añade respecto a las herramientas existentes, con qué nivel de severidad y qué contexto MITRE proporciona al analista L1.

**5. Limitaciones y falsos positivos documentados**
Qué deja sin cubrir, qué puede generar ruido y bajo qué condiciones la regla requeriría ajuste en producción.

**6. Regla Sigma**
Escrita con los keywords validados, guardada en `/opt/argos/sigma/rules/`, validada con `sigma check`, compilada con `sigma convert`.

**7. Regla XML Wazuh**
Escrita en `/var/ossec/etc/rules/`, validada con `wazuh-analysisd -t`, desplegada con reinicio del manager.

**8. Relación con escenarios anteriores - kill chain**
Cómo encaja el escenario en la secuencia de ataque, qué alerta precede a cuál y qué debe hacer el analista L1 cuando las ve correlacionadas.

**9. Validación empírica**
El ataque se ejecuta de nuevo. La alerta dispara. Se documenta con 3 capturas: ATK (el ataque), TEL/DASH (el dashboard) y LOG (el alerts.log del servidor).

---

## Proceso de validación · Los 9 puntos de cada regla YARA

Ninguna regla YARA de ARGOS existe sin pasar por estos 9 puntos. No hay excepciones.

**1. Contexto de la amenaza**
Qué artefacto genera el escenario en disco, qué posición ocupa en la kill chain y cómo complementa la capa de detección por comportamiento (Sigma/XML) ya desplegada para ese mismo escenario.

**2. Gap en repositorios públicos de YARA**
Qué existe en Neo23x0/signature-base, ANY.RUN/YARA, ReversingLabs y awesome-yara. Este paso es fundamental y no es opcional: antes de escribir cualquier regla se revisan los cuatro repositorios. ARGOS no crea reglas donde ya existe cobertura suficiente; solo construye detección original donde hay un gap real.

**3. Obtención de strings invariantes (empíricos o universalmente conocidos)**
Los strings se obtienen por dos vías complementarias: simulación empírica en laboratorio (el artefacto real se analiza con `yara -s` para identificar qué strings están presentes) o por conocimiento del dominio universalmente documentado en los repositorios de referencia (strings que la comunidad de malware analysis ha establecido como invariantes de una técnica). Ningún string se asume. La segunda vía requiere respaldo en al menos uno de los cuatro repositorios.

**4. Qué consigue ARGOS**
Qué cobertura añade respecto a las reglas públicas existentes, con qué condición lógica (`all of`, `N of`, invariante absoluto + indicadores secundarios) y qué contexto MITRE proporciona al analista L1.

**5. Limitaciones y falsos positivos documentados**
Qué variantes del artefacto no detecta la regla, qué puede generar ruido y bajo qué condiciones la regla requeriría ajuste en producción.

**6. Regla YARA**
Escrita con los strings validados, guardada en `/opt/argos/yara/rules/<bloque>/`, validada con `yarac`. Añadida al archivo maestro `argos_<bloque>_all.yar` via `include`.

**7. Integración con Wazuh via Active Response**
Pipeline completo: FIM realtime detecta archivo nuevo en ruta monitorizada → servidor ordena ejecutar `argos_yara_scan.py` en el agente (reglas 554/550/553) → script lee evento JSON de Wazuh via stdin, lanza `yara -s` contra el archivo maestro y escribe el match en `argos_yara_events.log` → logcollector envía al servidor → decoder `argos_yara` (program_name) extrae campos `yara_rule` y `yara_file` → regla base 103000 (level 10) + regla específica 103xxx (level según criticidad) disparan en el dashboard. Verificación previa con `wazuh-logtest`.

**8. Relación con escenarios anteriores - kill chain**
Cómo complementa la detección por comportamiento del mismo escenario y qué debe hacer el analista L1 cuando ve correlacionadas la alerta Sigma/XML y la alerta YARA del mismo artefacto.

**9. Validación empírica**
El artefacto se crea en el endpoint. La alerta 103xxx dispara en el dashboard. Se documenta con 3 capturas: ATK (el artefacto en disco), SCAN (salida de `yara -s` con los strings que hicieron match) y DASH/LOG (alerta 103xxx en el dashboard y alerts.log del servidor).

---

## Escenarios de ataque validados

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
| ESC19 | Desactivacion Defender/Wazuh/Sysmon | T1562.001 · Impair Defenses | ✅ |
| ESC20 | Exfiltracion via certutil/PowerShell LOLBAS | T1041 + T1105 | ✅ |
| ESC21 | Credential dumping LSASS/SAM | T1003.001 + T1003.002 | ✅ |
| ESC22 | Pass the Hash | T1550.002 · Pass the Hash | ✅ |
| ESC23 | LOLBAS: regsvr32, mshta, wmic | T1218 · System Binary Proxy Execution | ✅ |
| ESC24 | PowerShell obfuscado EncodedCommand | T1027 · Obfuscated Files or Information | ✅ |

### Bloque YARA · Linux · Endpoint 192.168.234.30

| # | Regla YARA | Escenario | Fase Kill Chain | MITRE | Estado |
| --- | --- | --- | --- | --- | --- |
| YARA-01 | Bash reverse shell script en disco | ESC05 | Execution | T1059.004 | ✅ |
| YARA-02 | Bash reverse shell en crontab | ESC06 | Persistence | T1053.003 | 🔨 |
| YARA-03 | Ingress tool transfer / herramienta descargada | ESC10 | C2 | T1105 | 🔨 |

### Bloque YARA · Windows · Endpoint 192.168.234.20

| # | Regla YARA | Escenario | Fase Kill Chain | MITRE | Estado |
| --- | --- | --- | --- | --- | --- |
| YARA-04 | PowerShell reverse shell TCPClient | ESC15 | Execution | T1059.001 | 🔨 |
| YARA-05 | Script PowerShell schtasks persistencia | ESC16 | Persistence | T1053.005 | 🔨 |
| YARA-06 | Ejecutable depositado en C:\Windows\ via SMB | ESC17/ESC18 | Lateral Movement | T1570 | 🔨 |
| YARA-07 | Script desactivación herramientas de seguridad | ESC19 | Defense Evasion | T1562.001 | 🔨 |
| YARA-08 | Archivo Base64 generado por certutil | ESC20 | Exfiltration | T1041 | 🔨 |
| YARA-09 | Mimikatz strings en binario | ESC21/ESC22 | Credential Access | T1003.001 | 🔨 |
| YARA-10 | LOLBAS con URL embebida | ESC23 | Defense Evasion | T1218 | 🔨 |
| YARA-11 | PowerShell ofuscado EncodedCommand | ESC24 | Defense Evasion | T1027 | 🔨 |

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
| Reglas YARA · YARA-01 validada · 10 reglas pendientes (YARA-02 a YARA-11) | 🔨 En desarrollo |
| Suricata IDS/IPS | 🔨 En desarrollo |
| Playbooks SOAR en Python | 🔨 En desarrollo |
| Triaje con LLM local (Ollama) | 🔨 En desarrollo |
| Alertas Telegram | 🔨 En desarrollo |
| Dashboard de supervisión humana | 🔨 En desarrollo |
| Integración PhishGuard | 🔨 En desarrollo |
| Evaluación cuantitativa (MTTD · MTTR · precisión LLM) | 📅 Pendiente |
| Release público completo | 📅 Q4 2026 |

---

## Estructura del repositorio

```
ARGOS/
├── detection/
│   ├── sigma/                  # Reglas Sigma propias (.yml) · Linux + Windows
│   ├── wazuh/                  # Reglas XML Wazuh propias · Linux + Windows
│   │   ├── active-response/    # Scripts Active Response YARA (argos_yara_scan.py)
│   │   ├── argos_yara_decoder.xml
│   │   └── argos_yara_rules.xml
│   └── yara/
│       ├── linux/              # Reglas YARA bloque Linux (YARA-01 a YARA-03)
│       └── windows/            # Reglas YARA bloque Windows (YARA-04 a YARA-11)
├── soar/                       # Playbooks SOAR en Python (en desarrollo)
├── dashboard/                  # Dashboard de supervisión humana (en desarrollo)
├── docs/
│   └── architecture/           # Diagramas de arquitectura
└── README.md
```

---

## Requisitos

- Wazuh Server 4.9.2 + agente Linux o Windows
- OpenSearch + OpenSearch Dashboards
- Sysmon v15+ con configuración SwiftOnSecurity (endpoints Windows)
- Python 3.10+
- sigma-cli
- YARA 4.1.3+ (`apt install yara`)
- Ollama con Mistral 7B o LLaMA 3 8B *(en desarrollo)*

---

## Autor

**Miguel Reguero** · Blue Team / SOC Analyst
[LinkedIn](https://www.linkedin.com/in/miguel-reguero/) · [GitHub](https://github.com/Miguel-R13) · [Portfolio](https://miguel-r13.github.io)
Máster en Ciberseguridad · IMMUNE × Universidad Nebrija × Banco Santander · Nota media 9,5/10
Top 5% TryHackMe · Autor de [PhishGuard](https://github.com/Miguel-R13/Phishguard)
