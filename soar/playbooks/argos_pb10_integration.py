#!/usr/bin/env python3
"""
ARGOS SOC - PB10 Beaconing / C2 Red - Integration Script (servidor .10)
Escalado humano: notifica al analista con contexto enriquecido.
NO ejecuta contencion automatica.

Triggers:
  - 110021: Beaconing / C2 de red detectado (SURICATA-ESC04/05/06/07)

Ejecucion: servidor Wazuh (.10) como servicio systemd argos-pb10
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
TRIGGER_RULES = {"110021"}
LOG_FILE = "/var/ossec/logs/argos_pb10_integration.log"


def log(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] PB10-BEACON | {message}"
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
        src_ip = data.get("src_ip", "desconocido")
        dest_ip = data.get("dest_ip", "desconocido")
        dest_port = data.get("dest_port", "desconocido")
        proto = data.get("proto", "desconocido")
        signature = data.get("alert", {}).get("signature", "desconocido")
        return {
            "rule_id": rule_id,
            "agent_name": alert.get("agent", {}).get("name", "desconocido"),
            "agent_ip": alert.get("agent", {}).get("ip", ""),
            "level": alert.get("rule", {}).get("level", 0),
            "rule_desc": alert.get("rule", {}).get("description", ""),
            "src_ip": src_ip,
            "dest_ip": dest_ip,
            "dest_port": dest_port,
            "proto": proto,
            "signature": signature,
        }
    except Exception:
        return None


def respond(alert):
    log(f"Alerta: rule {alert['rule_id']} | src {alert['src_ip']} -> dst {alert['dest_ip']}:{alert['dest_port']}")
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    mensaje = (
        f"🟠 <b>ARGOS SOC - PB10 BEACONING / C2 RED DETECTADO</b>\n\n"
        f"<b>Timestamp:</b> <code>{now}</code>\n"
        f"<b>Agente:</b> <code>{alert['agent_name']}</code>\n"
        f"<b>Regla:</b> <code>{alert['rule_id']}</code> (nivel {alert['level']})\n"
        f"<b>Firma Suricata:</b> {alert['signature']}\n\n"
        f"<b>IP origen:</b> <code>{alert['src_ip']}</code>\n"
        f"<b>IP destino:</b> <code>{alert['dest_ip']}</code>\n"
        f"<b>Puerto destino:</b> <code>{alert['dest_port']}</code>\n"
        f"<b>Protocolo:</b> <code>{alert['proto']}</code>\n\n"
        f"<b>Estado:</b> ESCALADO A ANALISTA - ACCION MANUAL REQUERIDA\n\n"
        f"<b>Acciones recomendadas:</b>\n"
        f"  - Verificar si la IP destino es un servidor legitimo\n"
        f"  - Analizar el patron de comunicacion (intervalos, volumenes)\n"
        f"  - Correlacionar con alertas de reverse shell o exfiltracion\n"
        f"  - Considerar bloqueo de la IP destino en el firewall perimetral\n\n"
        f"<i>ARGOS SOC - Decision humana requerida. No se ha ejecutado contencion automatica.</i>"
    )

    send_telegram(mensaje)
    log("Escalado completado.")


def main():
    log("=" * 60)
    log("PB10 Beaconing/C2 iniciado - Monitorizando alerts.json")
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
        log("PB10 detenido.")
        proc.terminate()


if __name__ == "__main__":
    main()
