# ARGOS · AI-Augmented SOC Detection & Response Platform
> *"30+ correcciones documentadas donde la IA dejó gaps que un analista L1 tuvo que cerrar."*

XDR open source con supervisión humana del modelo, construido desde cero sobre Wazuh.

No es un Wazuh instalado con las reglas por defecto. Es un sistema donde cada regla de detección nació de un ataque real ejecutado en laboratorio, cada gap en repositorios de referencia fue identificado por mí (Miguel Reguero, Blue Team Analyst) y cubierto con detección original propia, y cada corrección técnica sobre las propuestas de la IA está documentada con criterio profesional SOC.

---

## Las correcciones que la IA no hizo sola

Este es el núcleo de ARGOS. No un XDR bonito. Una demostración empírica de dónde falla la IA cuando diseña detección de seguridad sin supervisión profesional.

**La IA es la herramienta más potente que he usado en ciberseguridad. Y la que más supervisión necesita.**

Si construyes un sistema de detección con Claude Pro sin un analista encima corrigiéndola constantemente, el resultado parece completo pero deja pasar los ataques reales. ARGOS lo demuestra empíricamente con más de 30 correcciones documentadas en el Capítulo 14 de la memoria del proyecto.

**Algunos ejemplos reales:**

- La IA propuso quitar una regla de movimiento lateral porque generaba falsos positivos. Un sistema que sacrifica cobertura para reducir ruido es más peligroso que uno que no detecta nada.
- Para el bloque YARA propuso 4 reglas. El análisis sistemático de los 24 escenarios de la kill chain determinó que hacían falta 24. Sin ese análisis, más de la mitad de los vectores habrían quedado sin cubrir.
- En las reglas YARA de LOLBAS propuso una regla genérica para todos los vectores. Un SOC profesional necesita granularidad: la alerta tiene que identificar qué LOLBAS se abusó para que el analista L1 sepa cómo responder.
- Para mimikatz propuso una sola regla. Hay tres artefactos distintos con respuestas distintas: el script con comandos (se puede interceptar antes de ejecutar), el log con credenciales volcadas (el daño ya ocurrió), y el minidump de LSASS (compromiso total, cambiar todas las credenciales del dominio inmediatamente).
- Para PowerShell ofuscado propuso cubrir solo EncodedCommand. Faltan SecureString, GZip/Deflate, AMSI bypass y string manipulation: cuatro técnicas frecuentes en Emotet, QakBot y APTs documentadas en 2024-2025.
- Los strings de detección se limitaban al artefacto de laboratorio. Sin contrastar con Neo23x0, ANY.RUN/YARA y ReversingLabs, variantes reales documentadas en threat intelligence quedaban sin cubrir.

**El analista L1 no va a desaparecer. Va a dejar de mirar logs para convertirse en quien valida, interroga y corrige a la IA. ARGOS documenta exactamente eso.**

---

## Pilar filosófico

**ARGOS rebate la tesis de que el analista L1 va a desaparecer por la IA.**

El Capítulo 14 de la memoria del proyecto demuestra empíricamente que si ARGOS se hubiese construido solo con IA habría dejado múltiples gaps críticos de cobertura sin cubrir. En cada escenario identifiqué correcciones de criterio SOC que la IA no fue capaz de proponer por sí sola: umbrales incorrectos, vectores de ataque ignorados, telemetría mal clasificada, exclusiones necesarias no contempladas, cobertura YARA insuficiente.

La IA procesa. El analista decide. Y la diferencia entre los dos es exactamente lo que ARGOS documenta.

---

## Lo que diferencia a ARGOS

- **Detección original, no copiada.** Cada regla de detección nace de un ataque real ejecutado en laboratorio. Los repositorios de referencia (SigmaHQ para comportamiento, Neo23x0/ANY.RUN/ReversingLabs para contenido YARA) se usan para identificar gaps, no para copiar lo que ya existe.
- **Ningún campo se asume.** El ataque se simula primero, se analiza la telemetría, y solo entonces se escribe la regla. Nunca al revés.
- **Human-in-the-loop documentado.** El analista no solo supervisa alertas: supervisa la lógica de detección, identifica sus gaps y aprueba las acciones de respuesta. El Capítulo 14 registra cada corrección técnica donde el criterio profesional superó a la herramienta.
- **Kill chain completa, no escenarios aislados.** 24 escenarios en dos bloques: Linux (ESC01-ESC10) y Windows (ESC11-ESC24), desde el reconocimiento hasta la exfiltración y el credential dumping.
- **Evidencia de cada paso.** Cada escenario tiene capturas del ataque, la telemetría, el alerts.log y el dashboard. Nada sin validar.
- **Detección multicapa.** Comportamiento (Sigma/XML), contenido (YARA), red (Suricata) y triaje IA (Ollama) como capas complementarias e independientes.

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

| Capa | Tecnología |
| --- | --- |
| SIEM / XDR | **Wazuh 4.9.2** + OpenSearch Dashboards |
| Detección por comportamiento | Reglas **Sigma propias** (.yml) compiladas a OpenSearch via `sigma-cli` |
| Detección nativa | Reglas **XML Wazuh propias** creadas desde cero con validación empírica |
| Detección por contenido | **Reglas YARA propias** · 24 reglas sobre la kill chain ESC01-ESC24 ✅ |
| Telemetría Linux | **auditd** (syscalls), auth.log, ufw.log |
| Telemetría Windows - procesos | **Sysmon v15** (SwiftOnSecurity config) |
| Telemetría Windows - scripts | **ScriptBlock Logging** (Event ID 4104) |
| Telemetría Windows - autenticación | **Security Event Log** (EID 4625, 4624, 4698, 5157...) |
| Detección de red | **Suricata** IDS/IPS ✅ |
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
Qué detecta Wazuh por defecto, qué tiene SigmaHQ, qué queda sin cubrir y por qué importa ese gap. Este paso es fundamental y no es opcional: antes de escribir cualquier regla se revisa el repositorio SigmaHQ clonado localmente. ARGOS no crea reglas donde ya existe cobertura suficiente; solo construye detección original donde hay un gap real.

**3. Decisiones de diseño, telemetría y obtención de keywords empíricos**
El ataque se ejecuta en laboratorio y se analiza la telemetría real. Ningún campo se asume. Los keywords invariantes son los que aparecen en el log real.

**4. Qué consigue ARGOS**
Qué cobertura añade respecto a las herramientas existentes y qué contexto MITRE proporciona al analista L1.

**5. Limitaciones y falsos positivos documentados**
Qué deja sin cubrir, qué puede generar ruido y bajo qué condiciones requeriría ajuste en producción.

**6. Regla Sigma**
Escrita con los keywords validados, guardada en `/opt/argos/sigma/rules/`, validada con `sigma check`, compilada con `sigma convert`.

**7. Regla XML Wazuh**
Escrita en `/var/ossec/etc/rules/`, validada con `wazuh-analysisd -t`, desplegada con reinicio del manager.

**8. Relación con escenarios anteriores - kill chain**
Cómo encaja en la secuencia de ataque y qué debe hacer el analista L1 cuando ve las alertas correlacionadas.

**9. Validación empírica**
El ataque se ejecuta de nuevo. La alerta dispara. Se documenta con 3 capturas: ATK, TEL/DASH y LOG.

---

## Proceso de validación · Los 9 puntos de cada regla YARA

Ninguna regla YARA de ARGOS existe sin pasar por estos 9 puntos. No hay excepciones.

**1. Contexto de la amenaza**
Qué artefacto genera el escenario en disco y cómo complementa la capa de detección por comportamiento.

**2. Gap en repositorios públicos de YARA**
Qué existe en Neo23x0/signature-base, ANY.RUN/YARA, ReversingLabs y awesome-yara. No se crea ninguna regla donde ya existe cobertura suficiente.

**3. Obtención de strings invariantes**
Por vía empírica (análisis del artefacto real con `yara -s`) o por conocimiento del dominio documentado en los repositorios de referencia. Ningún string se asume.

**4. Qué consigue ARGOS**
Qué cobertura añade y qué contexto MITRE proporciona al analista L1.

**5. Limitaciones y falsos positivos documentados**
Qué variantes no detecta y bajo qué condiciones requeriría ajuste.

**6. Regla YARA**
Escrita con los strings validados, validada con `yarac`, añadida al archivo maestro via `include`.

**7. Integración con Wazuh via Active Response**
FIM realtime → servidor ordena script AR → yara -s → match en log → logcollector → decoder argos_yara → regla base 103000 + regla específica 103xxx en dashboard.

**8. Relación con escenarios anteriores - kill chain**
Cómo complementa la detección por comportamiento del mismo escenario.

**9. Validación empírica**
El artefacto se crea en el endpoint. La alerta 103xxx dispara. Se documenta con 4 capturas: ATK, SCAN, LOG y DASH.

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
| ESC23 | LOLBAS: regsvr32, mshta, certutil, bitsadmin, wmic | T1218 · System Binary Proxy Execution | ✅ |
| ESC24 | PowerShell ofuscado EncodedCommand | T1027 · Obfuscated Files or Information | ✅ |

### Bloque YARA · Linux · Endpoint 192.168.234.30

| # | Regla YARA | Escenario | Fase Kill Chain | MITRE | Estado |
| --- | --- | --- | --- | --- | --- |
| YARA-01 | Bash reverse shell script en disco | ESC05 | Execution | T1059.004 | ✅ |
| YARA-02 | Bash reverse shell en crontab | ESC06 | Persistence | T1053.003 | ✅ |
| YARA-03 | Ingress tool transfer ELF + C2 frameworks | ESC10 | C2 | T1105 | ✅ |
| YARA-04 | Reverse shell Python y Perl | ESC10 | Execution | T1059.006 | ✅ |
| YARA-05 | Webshell PHP y Python | ESC10/ESC08 | Persistence | T1505.003 | ✅ |

### Bloque YARA · Windows · Endpoint 192.168.234.20

| # | Regla YARA | Escenario | Fase Kill Chain | MITRE | Estado |
| --- | --- | --- | --- | --- | --- |
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
| Suricata IDS/IPS | ✅ Instalado y configurado · reglas en desarrollo |
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
│   │   ├── active-response/    # Scripts Active Response YARA
│   │   │   ├── argos_yara_scan.py      # Script AR Linux
│   │   │   └── argos_yara_scan_win.py  # Script AR Windows
│   │   ├── argos_yara_decoder.xml
│   │   └── argos_yara_rules.xml        # Reglas 103000-103024
│   ├── suricata/         # Reglas Suricata propias (.rules) · en desarrollo
│   └── yara/
│       ├── linux/              # 5 reglas YARA bloque Linux (YARA-01 a YARA-05)
│       └── windows/            # 19 reglas YARA bloque Windows (YARA-06 a YARA-24)
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
- Python 3.11+
- sigma-cli 3.0.3
- YARA 4.5.5
- Ollama con Mistral 7B o LLaMA 3 8B *(en desarrollo)*

---

## Autor

**Miguel Reguero** · Blue Team / SOC Analyst

[LinkedIn](https://www.linkedin.com/in/miguel-reguero/) · [GitHub](https://github.com/Miguel-R13) · [Portfolio](https://miguel-r13.github.io)

Máster en Ciberseguridad · IMMUNE × Universidad Nebrija × Banco Santander · Nota media 9,5/10

Top 5% TryHackMe · Autor de [PhishGuard](https://github.com/Miguel-R13/Phishguard)
```
