# ARGOS · AI-Augmented SOC Detection & Response Platform

> *"La IA propone. El analista decide. ARGOS documenta por qué importa la diferencia."*

**XDR open source con supervisión humana del modelo**, construido desde cero sobre Wazuh.  
No es un Wazuh instalado. Es un sistema de detección donde cada regla nació de un ataque real, cada gap fue identificado por un analista y cada corrección está documentada.

Trabajo de Fin de Máster · IMMUNE × Universidad Nebrija × Banco Santander · 2025-2026  
🔨 En desarrollo activo

---

## El problema que resuelve

Los SOC modernos se ahogan en alertas. El modelo clásico de L1 revisando cientos de eventos al día ya no escala. Pero el problema no es solo el volumen: es que la mayoría de entornos Wazuh se despliegan con las reglas por defecto, sin validar si realmente detectan lo que dicen detectar.

ARGOS parte de una premisa diferente: **ninguna regla de detección es válida hasta que un ataque real la dispara en laboratorio**.

Esto cambia todo el proceso. En lugar de copiar reglas de SigmaHQ y asumir que funcionan, ARGOS usa SigmaHQ como referencia para identificar los gaps, y construye detección original que cubre lo que las herramientas estándar no cubren. Cada escenario tiene su ataque simulado, su telemetría analizada, sus keywords validados empíricamente y su evidencia documentada.

El resultado es un XDR open source donde cada alerta tiene un origen trazable: sabes exactamente por qué dispara, qué ataque la genera y qué decisión tomó el analista cuando la IA no llegaba sola.

---

## Qué hace ARGOS que otros no hacen

**Detección propia, no heredada.** Las reglas Sigma y XML de ARGOS se construyen desde cero partiendo del comportamiento invariante del ataque, no de firmas de comandos que un atacante puede evadir cambiando un argumento. Cada campo de detección se confirma sobre telemetría real antes de escribirse.

**Gaps documentados con criterio profesional.** Cuando SigmaHQ filtra por LogonType 10 y los ataques reales de brute force RDP generan LogonType 3, ARGOS lo detecta y lo corrige. Cuando la IA propone un umbral de correlación sin considerar las diferencias entre Windows Firewall y UFW, el analista lo ajusta empíricamente. Todo queda registrado en la sección de Tuning de IA de la memoria del proyecto.

**Cobertura de kill chain completa.** No escenarios aislados: dos kill chains completas documentadas, una sobre endpoint Linux (ESC01-ESC10) y otra sobre endpoint Windows (ESC11-ESC24), siguiendo la secuencia real de un atacante desde el reconocimiento hasta la exfiltración.

**Human-in-the-loop como principio de diseño.** El analista no solo supervisa las alertas. Supervisa la lógica de detección, corrige sus gaps y aprueba las acciones de respuesta automatizada. La IA es una herramienta, no el centro del sistema.

**Telemetría multicapa en Windows.** Sysmon con configuración SwiftOnSecurity para procesos, red y registro. ScriptBlock Logging (EID 4104) para contenido de scripts PowerShell post-deobfuscación, invariante ante cualquier técnica de ofuscación. Security Event Log para autenticación y auditoría de objetos. Tres fuentes complementarias que juntas cierran los gaps que cada una deja por separado.

---

## Arquitectura

┌─────────────────────────────┐
                │     ARGOS · Wazuh Server     │
                │     192.168.234.10           │
                │                             │
                │  OpenSearch + Dashboards    │
                │  Reglas Sigma propias       │
                │  Reglas XML propias         │
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

---

## Stack

| Capa | Tecnología |
| --- | --- |
| SIEM / XDR | **Wazuh 4.9.2** + OpenSearch Dashboards |
| Detección por comportamiento | Reglas **Sigma propias** (.yml) compiladas a OpenSearch via `sigma-cli` |
| Detección nativa | Reglas **XML Wazuh propias** creadas desde cero con validación empírica |
| Telemetría Linux | **auditd** (syscalls), auth.log, ufw.log |
| Telemetría Windows - procesos | **Sysmon v15** (SwiftOnSecurity config) |
| Telemetría Windows - scripts | **ScriptBlock Logging** (Event ID 4104) |
| Telemetría Windows - autenticación | **Security Event Log** (EID 4625, 4624, 4698, 5157...) |
| Detección de red | **Suricata** IDS/IPS *(en desarrollo)* |
| Detección de contenido | **YARA** *(en desarrollo)* |
| Triaje IA | **Ollama** · Mistral 7B / LLaMA 3 8B, 100% local *(en desarrollo)* |
| Automatización | **Python** · Playbooks SOAR *(en desarrollo)* |
| Alertas | **Telegram** (severidad alta y crítica) *(en desarrollo)* |
| Módulo de phishing | **PhishGuard**, análisis estático offline de .eml *(en desarrollo)* |
| Framework de detección | **MITRE ATT&CK** |
| Framework de respuesta | **NIST** IR lifecycle |

---

## Proceso de validación · Los 9 puntos de cada escenario

Ninguna regla de ARGOS existe sin pasar por estos 9 puntos. No hay excepciones.

**1. Contexto de la amenaza**
Qué hace el atacante, qué posición ocupa en la kill chain, qué valor tiene para el adversario.

**2. Gap en herramientas nativas**
Qué detecta Wazuh por defecto, qué tiene SigmaHQ, qué queda sin cubrir y por qué importa ese gap.

**3. Decisiones de diseño, telemetría y obtención de keywords**
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

### Bloque Windows · Endpoint 192.168.234.20 · Kill chain en curso

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
| Reglas XML Wazuh propias · bloque Linux ESC01-ESC10 | ✅ Completado |
| Reglas XML Wazuh propias · bloque Windows ESC11-ESC16 | ✅ Completado |
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
- sigma-cli
- Ollama con Mistral 7B o LLaMA 3 8B *(en desarrollo)*

---

## Autor

**Miguel Reguero** · Blue Team / SOC Analyst  
[LinkedIn](https://www.linkedin.com/in/miguel-reguero/) · [GitHub](https://github.com/Miguel-R13) · [Portfolio](https://miguel-r13.github.io)  
Máster en Ciberseguridad · IMMUNE × Universidad Nebrija × Banco Santander · Nota media 9,5/10  
Top 5% TryHackMe · Autor de [PhishGuard](https://github.com/Miguel-R13/Phishguard)
