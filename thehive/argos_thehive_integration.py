#!/usr/bin/env python3
"""
ARGOS SOC - TheHive Integration - argos_thehive_integration.py
Monitoriza alerts.json en tiempo real y crea casos en TheHive para alertas
de nivel 13 o superior. Para alertas de nivel 10-12 notifica al analista
via Telegram para creacion manual del caso.

Flujo nivel 13+:
  1. Lee alerts.json en tiempo real
  2. Filtra alertas de nivel 13 o superior de reglas ARGOS
  3. Espera hasta 30 segundos a que el triaje LLM este disponible en cache
  4. Crea caso en TheHive via API REST con contexto completo del incidente
  5. Adjunta el triaje LLM como nota al caso
  6. Notifica a Telegram con enlace al caso

Flujo nivel 10-12:
  1. Lee alerts.json en tiempo real
  2. Filtra alertas de nivel 10-12 de reglas ARGOS
  3. Notifica a Telegram para creacion manual del caso por el analista

Ejecucion: servidor Wazuh (.10) como servicio systemd argos-thehive
Autor: ARGOS SOC - Miguel Reguero
"""

import json
import os
import time
import urllib.request
import urllib.error
from datetime import datetime

# === CONFIGURACION ===
ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"
TRIAGE_CACHE_FILE = "/var/ossec/logs/argos_triage_cache.json"
LOG_FILE = "/var/ossec/logs/argos_thehive_integration.log"

THEHIVE_URL = os.environ.get("THEHIVE_URL", "http://192.168.234.50:9000")
THEHIVE_API_KEY = os.environ.get("THEHIVE_API_KEY", "")

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "-5399235712")

MIN_LEVEL_AUTO = 13    # Nivel minimo para creacion automatica de caso
MIN_LEVEL_MANUAL = 10  # Nivel minimo para notificacion manual

TRIAGE_WAIT_SECONDS = 30  # Segundos maximos esperando triaje LLM

# IDs de reglas propias de ARGOS
ARGOS_RULE_IDS = set([str(i) for i in range(100001, 103025)] +
                     [str(i) for i in range(110001, 110022)])


# === LOGGING ===
def log(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] THEHIVE-INTEGRATION | {message}"
    print(entry, flush=True)
    try:
        with open(LOG_FILE, "a") as f:
            f.write(entry + "\n")
    except Exception:
        pass


# === TELEGRAM ===
def send_telegram(message):
    if not TELEGRAM_BOT_TOKEN:
        log("Telegram: token no configurado, saltando envio")
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = json.dumps({
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "HTML"
    }).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            log("Telegram: notificacion enviada correctamente.")
    except Exception as e:
        log(f"Telegram: ERROR - {e}")


# === THEHIVE API ===
def thehive_request(method, endpoint, data=None):
    url = f"{THEHIVE_URL}{endpoint}"
    payload = json.dumps(data).encode("utf-8") if data else None
    req = urllib.request.Request(
        url,
        data=payload,
        method=method,
        headers={
            "Authorization": f"Bearer {THEHIVE_API_KEY}",
            "Content-Type": "application/json"
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        log(f"TheHive HTTP ERROR {e.code}: {body}")
        return None
    except Exception as e:
        log(f"TheHive ERROR: {e}")
        return None


def create_case(alert, triage=None):
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    mitre = rule.get("mitre", {})
    nivel = rule.get("level", 0)
    rule_id = rule.get("id", "N/A")
    rule_desc = rule.get("description", "N/A")
    agent_name = agent.get("name", "N/A")
    agent_ip = agent.get("ip", "N/A")
    timestamp = alert.get("timestamp", "N/A")

    mitre_ids = ", ".join(mitre.get("id", [])) if mitre.get("id") else "N/A"
    mitre_techs = ", ".join(mitre.get("technique", [])) if mitre.get("technique") else "N/A"

    severidad = "Critical" if nivel >= 13 else "High" if nivel == 12 else "Medium"

    titulo = f"[ARGOS] {rule_desc} - {agent_name} (Rule {rule_id})"

    descripcion = f"""## Incidente detectado por ARGOS SOC

**Timestamp:** {timestamp}
**Rule ID:** {rule_id}
**Descripcion:** {rule_desc}
**Agente:** {agent_name} ({agent_ip})
**Nivel Wazuh:** {nivel}
**MITRE ATT&CK:** {mitre_ids} - {mitre_techs}

## Contexto del incidente

Este caso fue creado automaticamente por ARGOS SOC al detectar una alerta
de nivel {nivel} (CRITICA) en el endpoint {agent_name} ({agent_ip}).
"""

    case_data = {
        "title": titulo,
        "description": descripcion,
        "severity": 3 if nivel >= 13 else 2,
        "tags": [
            f"rule:{rule_id}",
            f"agent:{agent_name}",
            f"level:{nivel}",
            "argos-soc",
            "auto-created"
        ],
        "flag": True,
        "tlp": 2,
        "pap": 2
    }

    if mitre.get("id"):
        case_data["tags"] += [f"mitre:{m}" for m in mitre["id"]]

    log(f"Creando caso en TheHive: {titulo}")
    result = thehive_request("POST", "/api/v1/case", case_data)

    if not result:
        log("ERROR: no se pudo crear el caso en TheHive")
        return None

    case_id = result.get("_id") or result.get("id")
    case_number = result.get("number", "N/A")
    log(f"Caso creado: #{case_number} (id: {case_id})")

    # Adjuntar triaje LLM como tarea + log si esta disponible
    if triage and case_id:
        tarea_data = {
            "title": "Triaje ARGOS-LLM",
            "description": "Triaje automatico generado por Mistral 7B"
        }
        tarea_result = thehive_request("POST", f"/api/v1/case/{case_id}/task", tarea_data)
        if tarea_result:
            task_id = tarea_result.get("_id") or tarea_result.get("id")
            nota = f"## Triaje automatico ARGOS-LLM (Mistral 7B)\n\n{triage}\n\n---\n*Generado automaticamente por argos_triage_llm.py - Mistral 7B via Ollama*\n*El analista debe validar, corregir o rechazar esta recomendacion.*"
            log_data = {"message": nota}
            log_result = thehive_request("POST", f"/api/v1/task/{task_id}/log", log_data)
            if log_result:
                log(f"Triaje LLM adjuntado al caso #{case_number}")
            else:
                log(f"AVISO: no se pudo adjuntar el triaje al caso #{case_number}")
        else:
            log(f"AVISO: no se pudo crear tarea de triaje en caso #{case_number}")

    return case_id, case_number


# === CACHE TRIAGE ===
def get_triage_from_cache(alert_id, max_wait=TRIAGE_WAIT_SECONDS):
    log(f"Buscando triaje en cache para alert_id: {alert_id}")
    elapsed = 0
    while elapsed < max_wait:
        try:
            if os.path.exists(TRIAGE_CACHE_FILE):
                with open(TRIAGE_CACHE_FILE, "r") as f:
                    cache = json.load(f)
                if alert_id in cache:
                    log(f"Triaje encontrado en cache tras {elapsed}s")
                    return cache[alert_id].get("triage")
        except Exception as e:
            log(f"Cache ERROR: {e}")
        time.sleep(2)
        elapsed += 2
    log(f"Triaje no disponible tras {max_wait}s - creando caso sin nota LLM")
    return None


# === MONITOR PRINCIPAL ===
def monitor_alerts():
    log(f"Iniciando monitoreo de {ALERTS_FILE}")
    log(f"TheHive URL: {THEHIVE_URL}")
    log(f"Nivel auto (caso automatico): {MIN_LEVEL_AUTO}+")
    log(f"Nivel manual (notificacion): {MIN_LEVEL_MANUAL}-{MIN_LEVEL_AUTO - 1}")
    log("Esperando alertas nuevas...\n")

    processed = set()
    inicio = datetime.utcnow()

    with open(ALERTS_FILE, "r") as f:
        f.seek(0, 2)

        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue

            line = line.strip()
            if not line:
                continue

            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                continue

            rule = alert.get("rule", {})
            nivel = rule.get("level", 0)
            rule_id = rule.get("id", "")
            alert_id = alert.get("id", "")
            agent = alert.get("agent", {})

            # Filtrar alertas anteriores al inicio del script
            try:
                alert_ts = datetime.strptime(
                    alert.get("timestamp", "")[:19], "%Y-%m-%dT%H:%M:%S"
                )
                if alert_ts < inicio:
                    continue
            except Exception:
                pass

            # Filtrar por nivel minimo
            if nivel < MIN_LEVEL_MANUAL:
                continue

            # Solo alertas ARGOS propias o nivel critico
            if rule_id not in ARGOS_RULE_IDS and nivel < 13:
                continue

            # Evitar duplicados
            if alert_id in processed:
                continue
            processed.add(alert_id)

            rule_desc = rule.get("description", "N/A")
            agent_name = agent.get("name", "N/A")
            agent_ip = agent.get("ip", "N/A")

            log(f"ALERTA DETECTADA - Rule {rule_id} Nivel {nivel} - {agent_name}")

            # Nivel 13+: creacion automatica de caso
            if nivel >= MIN_LEVEL_AUTO:
                log(f"Nivel {nivel} - creacion automatica de caso en TheHive")
                triage = get_triage_from_cache(alert_id)
                result = create_case(alert, triage)
                if result:
                    case_id, case_number = result
                    emoji = "🔴"
                    msg = (
                        f"{emoji} <b>ARGOS SOC - Caso creado en TheHive</b>\n"
                        f"<b>Caso:</b> #{case_number}\n"
                        f"<b>Rule:</b> {rule_id} | <b>Nivel:</b> {nivel}\n"
                        f"<b>Agente:</b> {agent_name} ({agent_ip})\n"
                        f"<b>Descripcion:</b> {rule_desc}\n"
                        f"<b>Triaje LLM:</b> {'adjuntado' if triage else 'no disponible'}\n"
                        f"<b>URL:</b> {THEHIVE_URL}/cases/{case_number}"
                    )
                    send_telegram(msg)
                else:
                    log(f"ERROR al crear caso para alerta {alert_id}")
                    send_telegram(
                        f"🔴 <b>ARGOS SOC - ERROR TheHive</b>\n"
                        f"No se pudo crear caso para Rule {rule_id} Nivel {nivel}\n"
                        f"Agente: {agent_name} - Revisar log {LOG_FILE}"
                    )

            # Nivel 10-12: notificacion manual
            else:
                emoji = "🟠" if nivel == 12 else "🟡"
                msg = (
                    f"{emoji} <b>ARGOS SOC - Alerta nivel {nivel}</b>\n"
                    f"<b>Rule:</b> {rule_id} | <b>Nivel:</b> {nivel}\n"
                    f"<b>Agente:</b> {agent_name} ({agent_ip})\n"
                    f"<b>Descripcion:</b> {rule_desc}\n"
                    f"Accede a TheHive para crear el caso manualmente:\n"
                    f"{THEHIVE_URL}"
                )
                send_telegram(msg)
                log(f"Notificacion manual enviada para Rule {rule_id} Nivel {nivel}")


if __name__ == "__main__":
    monitor_alerts()
