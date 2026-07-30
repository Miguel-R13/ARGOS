# ARGOS · Augmented Response and Guidance Operations System

**SOC aumentado por IA** construido desde cero sobre **Wazuh**, con detección basada en reglas Sigma y XML propias, respuesta automatizada y supervisión humana del modelo.

Proyecto personal de investigación desarrollado como Trabajo de Fin de Máster  
IMMUNE × Universidad Nebrija × Banco Santander · 2025-2026  
🔨 En desarrollo activo

---

## Por qué existe ARGOS

Los SOC modernos generan más alertas de las que un analista puede procesar manualmente. El modelo clásico de L1 revisando cientos de eventos al día ya no escala, y las empresas están dejando de contratar perfiles que solo monitorizan para contratar perfiles que diseñan, supervisan y corrigen sistemas de detección automatizada.

ARGOS es la respuesta práctica a ese problema: un SOC funcional donde **Wazuh** actúa como SIEM central, las reglas de detección se escriben siguiendo el estándar **Sigma** y se validan empíricamente sobre ataques reales en laboratorio, y un **LLM local (Ollama)** asiste al analista en el triaje sin que ningún dato abandone el entorno.

El objetivo no es automatizar al analista. Es demostrar que un profesional capaz de construir, afinar y supervisar este sistema vale más que uno que solo lo opera.

---

## Qué hace

- Detecta amenazas reales en endpoints Linux y Windows mediante reglas Sigma compiladas a Wazuh y reglas XML nativas, validadas empíricamente sobre 10 escenarios de ataque reales
- Alerta al analista vía Telegram para eventos de severidad alta y crítica, sin ruido
- Enriquece cada alerta con contexto MITRE ATT&CK antes de presentarla
- Triaje asistido por LLM local (Ollama / Mistral / LLaMA): severidad, TTP probable y acción sugerida, sin enviar datos a la nube
- Responde automáticamente mediante playbooks SOAR en Python para las acciones de orquestación; las acciones de impacto activo requieren aprobación del analista (human-in-the-loop)
- Analiza phishing integrando PhishGuard como módulo offline: veredicto CLEAN/SUSPICIOUS/MALICIOUS en menos de 1 segundo

---

## Stack

| Capa | Tecnología |
|---|---|
| SIEM | **Wazuh** + OpenSearch Dashboards |
| Detección por comportamiento | Reglas **Sigma** (.yml) compiladas a XML via `sigma-cli` |
| Detección nativa | Reglas **XML Wazuh** propias con tuning sobre reglas de la comunidad |
| Detección de contenido | **YARA** |
| Telemetría de kernel | **auditd** (Linux) |
| Triaje IA | **Ollama** · Mistral 7B / LLaMA 3 8B, ejecución 100% local |
| Automatización | **Python** · Playbooks SOAR |
| Alertas | **Telegram** (severidad alta y crítica) |
| Módulo de phishing | **PhishGuard**, análisis estático offline de .eml |
| Framework de detección | **MITRE ATT&CK** |
| Framework de respuesta | **NIST** IR lifecycle |

---

## Motor de detección · Proceso de validación empírica

Cada regla de ARGOS sigue un proceso estricto de 7 pasos. No se asume ningún campo ni keyword teórico: todo se valida sobre telemetría real antes de escribir una sola línea de regla.

**1. Simulación exploratoria previa**  
Se ejecuta el ataque en el laboratorio y se analiza la telemetría real para identificar los keywords invariantes del escenario. Nunca se parte de documentación teórica.

**2. Regla Sigma**  
Con los keywords validados empíricamente se escribe la regla Sigma siguiendo la especificación SigmaHQ, se guarda en `/opt/argos/sigma/rules/`, se valida con `sigma check` y se compila con `sigma convert` guardando el resultado en `/opt/argos/sigma/compiled/`.

**3. Regla XML Wazuh**  
Se escribe la regla XML en `/var/ossec/etc/rules/`, se valida con `sudo /var/ossec/bin/wazuh-analysisd -t` y se aplica con `sudo systemctl restart wazuh-manager`.

**4. Simulación de validación**  
Se vuelve a ejecutar el ataque para confirmar que la regla dispara correctamente.

**5. Verificación en alerts.log**  
Se confirma la alerta en `/var/ossec/logs/alerts/alerts.log`.

**6. Verificación en dashboard**  
Se filtra por nivel de severidad en Threat Hunting, como lo haría un analista L1, nunca por `rule.id`.

**7. Evidencia**  
Screenshots de cada fase: ATK · TEL · LOG · DASH.

---

## Escenarios de ataque validados

Todos los escenarios están implementados sobre endpoint **Linux**. Endpoint **Windows** en desarrollo.

| # | Escenario | TTP MITRE ATT&CK | Estado |
|---|---|---|---|
| 01 | Fuerza bruta SSH | T1110 · Brute Force | ✅ |
| 02 | Escalada de privilegios con sudo | T1548.003 · Sudo and Sudo Caching | ✅ |
| 03 | Reconocimiento de red con Nmap | T1046 · Network Service Discovery | ✅ |
| 04 | Enumeración de usuarios | T1087.001 · Account Discovery | ✅ |
| 05 | Movimiento lateral SSH | T1021.004 · Remote Services: SSH | ✅ |
| 06 | Transferencia lateral SCP/SFTP | T1570 · Lateral Tool Transfer | ✅ |
| 07 | Reverse shell | T1059.004 · Command and Scripting Interpreter | ✅ |
| 08 | Cron job malicioso | T1053.003 · Scheduled Task/Job: Cron | ✅ |
| 09 | Exfiltración de datos vía curl/wget | T1041 + T1105 | ✅ |
| 10 | Desactivación de herramientas de seguridad | T1562.001 · Impair Defenses | ✅ |

---

## Estado y roadmap

| Componente | Estado |
|---|---|
| Wazuh SIEM + OpenSearch + agentes | ✅ Implementado |
| Reglas Sigma (.yml) · 10 escenarios | ✅ Implementado |
| Reglas XML Wazuh · 10 escenarios | ✅ Implementado |
| Endpoint Linux | ✅ Implementado |
| Alertas Telegram (severidad alta/crítica) | 🔨 En desarrollo |
| Reglas YARA | 🔨 En desarrollo |
| Endpoint Windows | 🔨 En desarrollo |
| Playbooks SOAR en Python | 🔨 En desarrollo |
| Triaje con LLM local (Ollama) | 🔨 En desarrollo |
| Dashboard de supervisión humana | 🔨 En desarrollo |
| Integración PhishGuard | 🔨 En desarrollo |
| Evaluación cuantitativa (MTTD · MTTR · precisión LLM) | 📅 Pendiente |
| Release público completo | 📅 Q3 2026 |

---

## Estructura del repositorio

```
ARGOS/
├── detection/
│   ├── sigma/          # Reglas Sigma (.yml) · estándar SigmaHQ
│   ├── wazuh/          # Reglas XML Wazuh compiladas y validadas
│   └── yara/           # Reglas YARA (en desarrollo)
├── soar/
│   └── playbooks/      # Playbooks SOAR en Python (en desarrollo)
├── dashboard/          # Dashboard de supervisión humana (en desarrollo)
├── docs/
│   └── architecture/   # Diagramas de arquitectura
└── README.md
```

---

## Requisitos

- Wazuh Server 4.x + agente Linux o Windows
- OpenSearch + OpenSearch Dashboards
- Python 3.10+
- sigma-cli (para compilar reglas Sigma)
- Ollama con Mistral 7B o LLaMA 3 8B *(módulo de triaje, en desarrollo)*

---

## Autor

**Miguel Reguero** · Blue Team / SOC Analyst  
[LinkedIn](https://www.linkedin.com/in/miguel-reguero/) · [GitHub](https://github.com/Miguel-R13) · [Portfolio](https://miguel-r13.github.io)  
Máster en Ciberseguridad · IMMUNE × Universidad Nebrija × Banco Santander · Nota media 9,5/10  
Top 5% TryHackMe · Autor de [PhishGuard](https://github.com/Miguel-R13/Phishguard)
