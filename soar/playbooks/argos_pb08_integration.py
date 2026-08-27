#!/usr/bin/env python3
"""
ARGOS SOC - PB08 Credential Dumping / LSASS - Integration Script (servidor .10)
Escalado humano OBLIGATORIO: notifica al analista con contexto forense enriquecido.
NO ejecuta contencion automatica - ejemplo empirico central del argumento del TFM.

Razon del escalado obligatorio:
  - LSASS puede ser accedido por procesos legitimos (AV, EDR)
  - Matar el proceso puede destruir evidencia forense
  - La decision requiere criterio humano sin excepcion

Triggers:
  - 102103: Credential dumping / LSASS Windows (ESC21/ESC22)

Ejecucion: servidor Wazuh (.10) como servicio systemd argos-pb08
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
TRIGGER_RULES = {"102103"}
LOG_FILE = "/var/ossec/logs/argos_pb08_integration.log"


def log(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] PB08-CREDUMP | {message}"
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
        data = alert.get("data", {}).get("win", {})
        image = data.get("eventdata", {}).get("image", "desconocido")
        target_image = data.get("eventdata", {}).get("targetImage", "desconocido")
        granted_access = data.get("eventdata", {}).get("grantedAccess", "desconocido")
        source_pid = data.get("eventdata", {}).get("sourceProcessId", "desconocido")
        return {
            "rule_id": rule_id,
            "agent_name": alert.get("agent", {}).get("name", "desconocido"),
            "agent_ip": alert.get("agent", {}).get("ip", ""),
            "level": alert.get("rule", {}).get("level", 0),
            "rule_desc": alert.get("rule", {}).get("description", ""),
            "image": image,
            "target_image": target_image,
            "granted_access": granted_access,
            "source_pid": source_pid,
        }
    except Exception:
        return None


def respond(alert):
    log(f"ALERTA CRITICA: rule {alert['rule_id']} | agente {alert['agent_name']} | proceso {alert['image']}")
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    mensaje = (
        f"🔴 <b>ARGOS SOC - PB08 CREDENTIAL DUMPING / LSASS DETECTADO</b>\n\n"
        f"<b>Timestamp:</b> <code>{now}</code>\n"
        f"<b>Agente:</b> <code>{alert['agent_name']}</code> ({alert['agent_ip']})\n"
        f"<b>Regla:</b> <code>{alert['rule_id']}</code> (nivel {alert['level']})\n"
        f"<b>Descripcion:</b> {alert['rule_desc']}\n\n"
        f"<b>Proceso origen:</b> <code>{alert['image']}</code>\n"
        f"<b>PID origen:</b> <code>{alert['source_pid']}</code>\n"
        f"<b>Proceso objetivo:</b> <code>{alert['target_image']}</code>\n"
        f"<b>Acceso concedido:</b> <code>{alert['granted_access']}</code>\n\n"
        f"<b>Estado:</b> ESCALADO HUMANO OBLIGATORIO\n\n"
        f"<b>ATENCION:</b> NO matar el proceso automaticamente.\n"
        f"<b>Acciones recomendadas:</b>\n"
        f"  - Verificar si el proceso origen es un AV o EDR legitimo\n"
        f"  - Si es malicioso: preservar evidencia forense antes de actuar\n"
        f"  - Crear volcado de memoria del proceso sospechoso\n"
        f"  - Aislar el endpoint de la red antes de matar el proceso\n"
        f"  - Considerar respuesta a incidente completa\n\n"
        f"<i>ARGOS SOC - La IA propone, el analista decide. Contencion automatica desactivada por diseno.</i>"
    )

    send_telegram(mensaje)
    log("Escalado obligatorio completado.")


def main():
    log("=" * 60)
    log("PB08 Credential Dumping iniciado - Monitorizando alerts.json")
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
        log("PB08 detenido.")
        proc.terminate()


if __name__ == "__main__":
    main()
