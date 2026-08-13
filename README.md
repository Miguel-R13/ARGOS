# ARGOS · Augmented Response and Guidance Operations System

**XDR open source aumentado por IA** construido desde cero sobre **Wazuh**, con detección basada en reglas Sigma y XML propias creadas desde cero, respuesta automatizada y supervisión humana del modelo.

Proyecto personal de investigación desarrollado como Trabajo de Fin de Máster  
IMMUNE × Universidad Nebrija × Banco Santander · 2025-2026  
🔨 En desarrollo activo

---

## Por qué existe ARGOS

Los SOC modernos generan más alertas de las que un analista puede procesar manualmente. El modelo clásico de L1 revisando cientos de eventos al día ya no escala, y las empresas están dejando de contratar perfiles que solo monitorizan para contratar perfiles que diseñan, supervisan y corrigen sistemas de detección automatizada.

ARGOS es la respuesta práctica a ese problema: un XDR open source construido sobre Wazuh que correlaciona telemetría de múltiples dominios en un único punto de visibilidad.

En el dominio de endpoint, los agentes Wazuh en Linux y Windows actúan como la capa de detección base. En Windows, Sysmon con configuración SwiftOnSecurity enriquece la telemetría con creación de procesos, conexiones de red, modificaciones de registro y carga de módulos. ScriptBlock Logging captura el contenido de scripts PowerShell post-deobfuscación. En Linux, auditd proporciona telemetría de syscalls, acceso a archivos sensibles y ejecución de comandos privilegiados.

El enfoque de detección es deliberadamente distinto al estándar: en lugar de desplegar reglas existentes, se parte de SigmaHQ como referencia para identificar los gaps de cobertura, y se construyen desde cero reglas Sigma propias y reglas XML Wazuh personales validadas empíricamente sobre ataques reales en laboratorio. Ningún campo de detección se asume: todo se confirma sobre telemetría real antes de escribir una sola línea de regla.

En el dominio de red, Suricata actuará como IDS/IPS complementario analizando el tráfico entre segmentos, con sus alertas integradas en Wazuh para correlación centralizada.

Las alertas de mayor severidad se envían via Telegram al analista en tiempo real, además de estar disponibles en el dashboard de Wazuh. Un LLM local (Ollama con Mistral o LLaMA) asistirá en el triaje sin que ningún dato abandone el entorno. Los playbooks SOAR en Python automatizarán la respuesta, con aprobación humana obligatoria para las acciones de impacto activo.

El objetivo no es automatizar al analista. Es demostrar que un profesional capaz de construir, afinar y supervisar un sistema de este tipo vale más que uno que solo lo opera.

---

## Qué hace

- Detecta amenazas reales en endpoints Linux y Windows mediante reglas Sigma y XML propias creadas desde cero, partiendo de SigmaHQ para identificar gaps y cubrirlos con detección original validada empíricamente sobre ataques reales
- Telemetría enriquecida en Windows via **Sysmon** (SwiftOnSecurity config), **ScriptBlock Logging** (EID 4104) y **Security Event Log**
- Telemetría en Linux via **auditd**, auth.log y ufw.log
- Analiza tráfico de red via **Suricata** como capa IDS/IPS complementaria *(en desarrollo)*
- Alerta al analista via **Telegram** para eventos de severidad alta y crítica, sin ruido *(en desarrollo)*
- Enriquece cada alerta con contexto **MITRE ATT&CK** antes de presentarla
- Triaje asistido por **LLM local** (Ollama / Mistral / LLaMA): severidad, TTP probable y acción sugerida, sin enviar datos a la nube *(en desarrollo)*
- Responde automáticamente mediante **playbooks SOAR** en Python; las acciones de impacto activo requieren aprobación del analista (human-in-the-loop) *(en desarrollo)*
- Analiza phishing integrando **PhishGuard** como módulo offline: veredicto CLEAN/SUSPICIOUS/MALICIOUS en menos de 1 segundo *(en desarrollo)*

---

## Stack

| Capa | Tecnología |
| --- | --- |
| SIEM / XDR | **Wazuh 4.9.2** + OpenSearch Dashboards |
| Detección por comportamiento | Reglas **Sigma** propias (.yml) compiladas a OpenSearch via `sigma-cli` |
| Detección nativa | Reglas **XML Wazuh** propias creadas desde cero con validación empírica |
| Detección de contenido | **YARA** *(en desarrollo)* |
| Telemetría Linux | **auditd**, auth.log, ufw.log |
| Telemetría Windows - procesos | **Sysmon** v15 (SwiftOnSecurity config) |
| Telemetría Windows - scripts | **ScriptBlock Logging** (Event ID 4104) |
| Telemetría Windows - autenticación | **Security Event Log** (EID 4625, 4624, 4698, 5157...) |
| Detección de red | **Suricata** IDS/IPS *(en desarrollo)* |
| Triaje IA | **Ollama** · Mistral 7B / LLaMA 3 8B, ejecución 100% local *(en desarrollo)* |
| Automatización | **Python** · Playbooks SOAR *(en desarrollo)* |
| Alertas | **Telegram** (severidad alta y crítica) *(en desarrollo)* |
| Módulo de phishing | **PhishGuard**, análisis estático offline de .eml *(en desarrollo)* |
| Framework de detección | **MITRE ATT&CK** |
| Framework de respuesta | **NIST** IR lifecycle |

---

## Motor de detección · Proceso de validación empírica

Cada regla de ARGOS sigue un proceso estricto de 9 puntos. No se asume ningún campo ni keyword teórico: todo se valida sobre telemetría real antes de escribir una sola línea de regla.

1. **Contexto de la amenaza** - Qué hace el atacante, qué telemetría genera, qué keywords son invariantes
2. **Gap en herramientas nativas** - Qué cubre Wazuh y SigmaHQ, qué deja sin cubrir
3. **Simulación exploratoria previa** - Ataque real en laboratorio para descubrir keywords empíricamente
4. **Regla Sigma** - Escrita con keywords validados, guardada en `/opt/argos/sigma/rules/`, validada con `sigma check`, compilada con `sigma convert`
5. **Regla XML Wazuh** - Escrita en `/var/ossec/etc/rules/`, validada con `wazuh-analysisd -t`, aplicada con reinicio del manager
6. **Simulación de validación** - Ataque de nuevo para confirmar que la regla dispara
7. **Verificación en alerts.log** - Confirmación en `/var/ossec/logs/alerts/alerts.log`
8. **Verificación en dashboard** - Filtrado por nivel de severidad en Threat Hunting como lo haría un analista L1
9. **Evidencia** - Screenshots de cada fase: ATK · TEL · LOG · DASH

---

## Escenarios de ataque validados

### Bloque Linux · Endpoint 192.168.234.30

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

### Bloque Windows · Endpoint 192.168.234.20

| # | Escenario | TTP MITRE ATT&CK | Estado |
| --- | --- | --- | --- |
| ESC11 | Reconocimiento de red con Nmap | T1046 · Network Service Discovery | ✅ |
| ESC12 | Fuerza bruta RDP | T1110 · Brute Force | ✅ |
| ESC13 | Enumeración de usuarios Windows | T1087.001 · Account Discovery | ✅ |
| ESC14 | Escalada de privilegios UAC bypass fodhelper | T1548.002 · Bypass UAC | ✅ |
| ESC15 | Reverse shell PowerShell | T1059.001 · PowerShell | ✅ |
| ESC16 | Persistencia via tareas programadas | T1053.005 · Scheduled Task | ✅ |
| ESC17 | Movimiento lateral SMB/WMI | T1021.002 · SMB/Windows Admin Shares | 🔨 |
| ESC18 | Transferencia lateral via SMB | T1570 · Lateral Tool Transfer | 🔨 |
| ESC19 | Desactivación Defender/Wazuh | T1562.001 · Impair Defenses | 🔨 |
| ESC20 | Exfiltración via PowerShell/certutil | T1041 · Exfiltration Over C2 | 🔨 |
| ESC21 | Credential dumping LSASS/SAM | T1003.001 · LSASS Memory | 🔨 |
| ESC22 | Pass the Hash | T1550.002 · Pass the Hash | 🔨 |
| ESC23 | LOLBAS: certutil, regsvr32, mshta | T1218 · System Binary Proxy Execution | 🔨 |
| ESC24 | PowerShell obfuscado | T1027 · Obfuscated Files or Information | 🔨 |

---

## Estado y roadmap

| Componente | Estado |
| --- | --- |
| Wazuh 4.9.2 + OpenSearch + agentes | ✅ Implementado |
| Sysmon v15 (SwiftOnSecurity) en endpoint Windows | ✅ Implementado |
| ScriptBlock Logging en endpoint Windows | ✅ Implementado |
| Reglas Sigma propias · 26 reglas (10 Linux + 16 Windows) | ✅ Implementado |
| Reglas XML Wazuh propias · bloque Linux completo | ✅ Implementado |
| Reglas XML Wazuh propias · bloque Windows ESC11-ESC16 | ✅ Implementado |
| Bloque Linux ESC01-ESC10 · kill chain completa | ✅ Completado |
| Bloque Windows ESC11-ESC16 | ✅ Completado |
| Bloque Windows ESC17-ESC24 | 🔨 En desarrollo |
| Suricata IDS/IPS | 🔨 En desarrollo |
| Reglas YARA | 🔨 En desarrollo |
| Playbooks SOAR en Python | 🔨 En desarrollo |
| Triaje con LLM local (Ollama) | 🔨 En desarrollo |
| Alertas Telegram | 🔨 En desarrollo |
| Dashboard de supervisión humana | 🔨 En desarrollo |
| Integración PhishGuard | 🔨 En desarrollo |
| Evaluación cuantitativa (MTTD · MTTR · precisión LLM) | 📅 Pendiente |
| Release público completo | 📅 Q4 2026 |

---

## Estructura del repositorio

ARGOS/
├── detection/
│ ├── sigma/ # Reglas Sigma propias (.yml) · Linux + Windows
│ ├── wazuh/ # Reglas XML Wazuh propias · Linux + Windows
│ └── yara/ # Reglas YARA (en desarrollo)
├── soar/
│ └── playbooks/ # Playbooks SOAR en Python (en desarrollo)
├── dashboard/ # Dashboard de supervisión humana (en desarrollo)
├── docs/
│ └── architecture/ # Diagramas de arquitectura
└── README.md

---

## Requisitos

- Wazuh Server 4.9.2 + agente Linux o Windows
- OpenSearch + OpenSearch Dashboards
- Sysmon v15+ con configuración SwiftOnSecurity (endpoints Windows)
- Python 3.10+
- sigma-cli (para compilar reglas Sigma)
- Ollama con Mistral 7B o LLaMA 3 8B *(módulo de triaje, en desarrollo)*

---

## Autor

**Miguel Reguero** · Blue Team / SOC Analyst  
[LinkedIn](https://www.linkedin.com/in/miguel-reguero/) · [GitHub](https://github.com/Miguel-R13) · [GitHub](https://github.com/Miguel-R13) · [Portfolio](https://miguel-r13.github.io)  
Máster en Ciberseguridad · IMMUNE × Universidad Nebrija × Banco Santander · Nota media 9,5/10  
Top 5% TryHackMe · Autor de [PhishGuard](https://github.com/Miguel-R13/Phishguard)
