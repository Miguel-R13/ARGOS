#!/usr/bin/env python3
"""
ARGOS SOC - PB06 Desactivacion de herramientas de seguridad - Integration Script (servidor .10)
Escalado humano: notifica al analista con contexto enriquecido.
NO ejecuta contencion automatica.

Triggers:
  - 100902: Desactivacion herramientas Linux (ESC09)
  - 101906: Desactivacion herramientas Windows (ESC19)

Ejecucion: servidor Wazuh (.10) como servicio systemd argos-pb06
Autor: ARGOS SOC - Miguel Reguero
"""

import sys
import os
import json
import subprocess
import urllib.request
from datetime import datetime

TELEGRAM_BOT_TOKEN = "***REMOVED***"
TELEGRAM_CHAT_ID = "-5399235712"
ALERTS_JSON = "/var/ossec/logs/alerts/alerts.json"
TRIGGER_RULES = {"100902", "101906"}
LOG_FILE = "/var/ossec/logs/argos_pb06_integration.log"


def log(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] PB06-DEFENSE | {message}"
    print(entry, flush=True)
    try:
        with open(LOG_FILE, "a") as f:
            f.write(entry + "\n")
    except Exception:
        pass


def send_telegram(message):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = json.dumps({
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "HTML"
    }).encode("utf-8")
    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10):
            log("Telegram: notificacion enviada correctamente.")
    except Exception as e:
        log(f"Telegram: ERROR - {e}")


def parse_alert(line):
    try:
        alert = json.loads(line.strip())
        rule_id = alert.get("rule", {}).get("id", "")
        if rule_id not in TRIGGER_RULES:
            return None
        data = alert.get("data", {})
        exe = (
            data.get("audit", {}).get("exe") or
            data.get("win", {}).get("eventdata", {}).get("image") or
            "desconocido"
        )
        return {
            "rule_id": rule_id,
            "agent_name": alert.get("agent", {}).get("name", "desconocido"),
            "agent_ip": alert.get("agent", {}).get("ip", ""),
            "level": alert.get("rule", {}).get("level", 0),
            "rule_desc": alert.get("rule", {}).get("description", ""),
            "exe": exe,
            "full_log": alert.get("full_log", "")[:300],
        }
    except Exception:
        return None


def respond(alert):
    log(f"Alerta: rule {alert['rule_id']} | agente {alert['agent_name']} | exe {alert['exe']}")
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    mensaje = (
        f"🔴 <b>ARGOS SOC - PB06 DESACTIVACION DE HERRAMIENTAS DE SEGURIDAD</b>\n\n"
        f"<b>Timestamp:</b> <code>{now}</code>\n"
        f"<b>Agente:</b> <code>{alert['agent_name']}</code> ({alert['agent_ip']})\n"
        f"<b>Regla:</b> <code>{alert['rule_id']}</code> (nivel {alert['level']})\n"
        f"<b>Descripcion:</b> {alert['rule_desc']}\n"
        f"<b>Proceso:</b> <code>{alert['exe']}</code>\n\n"
        f"<b>Estado:</b> ALERTA CRITICA - ACCION INMEDIATA REQUERIDA\n\n"
        f"<b>Acciones recomendadas:</b>\n"
        f"  - Verificar si Wazuh, Sysmon o Defender siguen activos en el endpoint\n"
        f"  - Revisar quien ejecuto el proceso de desactivacion\n"
        f"  - Considerar aislamiento inmediato del endpoint\n"
        f"  - Iniciar investigacion forense\n\n"
        f"<i>ARGOS SOC - Decision humana requerida. El SIEM puede quedar ciego si no se actua.</i>"
    )

    send_telegram(mensaje)
    log("Escalado completado.")


def main():
    log("=" * 60)
    log("PB06 Desactivacion herramientas iniciado - Monitorizando alerts.json")
    log(f"Triggers: {TRIGGER_RULES}")
    log("=" * 60)

    if not os.path.exists(ALERTS_JSON):
        log(f"ERROR: {ALERTS_JSON} no existe.")
        sys.exit(1)

    proc = subprocess.Popen(
        ["tail", "-f", "-n", "0", ALERTS_JSON],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )

    log("Esperando alertas...")

    try:
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            alert = parse_alert(line)
            if alert:
                respond(alert)
    except KeyboardInterrupt:
        log("PB06 detenido.")
        proc.terminate()


if __name__ == "__main__":
    main()
