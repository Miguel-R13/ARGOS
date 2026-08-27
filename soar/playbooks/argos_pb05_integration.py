#!/usr/bin/env python3
"""
ARGOS SOC - PB05 Movimiento Lateral - Integration Script (servidor .10)
Escalado humano: notifica al analista con contexto enriquecido.
NO ejecuta contencion automatica.

Triggers:
  - 100501: SSH lateral movement Linux (ESC07)
  - 101703: SMB/psexec lateral movement Windows (ESC17)

Ejecucion: servidor Wazuh (.10) como servicio systemd argos-pb05
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
TRIGGER_RULES = {"100501", "101703"}
LOG_FILE = "/var/ossec/logs/argos_pb05_integration.log"


def log(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] PB05-LATERAL | {message}"
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
        return {
            "rule_id": rule_id,
            "agent_id": alert.get("agent", {}).get("id", ""),
            "agent_name": alert.get("agent", {}).get("name", "desconocido"),
            "agent_ip": alert.get("agent", {}).get("ip", ""),
            "level": alert.get("rule", {}).get("level", 0),
            "rule_desc": alert.get("rule", {}).get("description", ""),
            "srcip": alert.get("data", {}).get("srcip", "desconocido"),
            "full_log": alert.get("full_log", "")[:300],
        }
    except Exception:
        return None


def respond(alert):
    log(f"Alerta: rule {alert['rule_id']} | agente {alert['agent_name']} | src {alert['srcip']}")
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    mensaje = (
        f"🟠 <b>ARGOS SOC - PB05 MOVIMIENTO LATERAL DETECTADO</b>\n\n"
        f"<b>Timestamp:</b> <code>{now}</code>\n"
        f"<b>Agente:</b> <code>{alert['agent_name']}</code> ({alert['agent_ip']})\n"
        f"<b>Regla:</b> <code>{alert['rule_id']}</code> (nivel {alert['level']})\n"
        f"<b>Descripcion:</b> {alert['rule_desc']}\n"
        f"<b>IP origen:</b> <code>{alert['srcip']}</code>\n\n"
        f"<b>Estado:</b> ESCALADO A ANALISTA - ACCION MANUAL REQUERIDA\n\n"
        f"<b>Acciones recomendadas:</b>\n"
        f"  - Verificar si la IP origen es un activo legitimo de la red\n"
        f"  - Revisar la sesion SSH/SMB establecida\n"
        f"  - Correlacionar con alertas previas del mismo origen\n"
        f"  - Considerar aislamiento del endpoint si el movimiento es malicioso\n\n"
        f"<i>ARGOS SOC - Decision humana requerida. No se ha ejecutado contencion automatica.</i>"
    )

    send_telegram(mensaje)
    log("Escalado completado.")


def main():
    log("=" * 60)
    log("PB05 Movimiento Lateral iniciado - Monitorizando alerts.json")
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
        log("PB05 detenido.")
        proc.terminate()


if __name__ == "__main__":
    main()
