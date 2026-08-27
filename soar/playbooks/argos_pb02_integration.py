#!/usr/bin/env python3
"""
ARGOS SOC - PB02 Brute Force SSH - Integration Script (servidor .10)
Monitoriza alerts.json en tiempo real, detecta rule 100103 (SSH brute force confirmado)
y ejecuta contencion activa via SSH en el endpoint Linux afectado.

Flujo:
  1. Lee alerts.json en tiempo real (tail -f)
  2. Filtra alertas de rule 100103 desde agente 002 (ARGOS-Endpoint-Linux)
  3. Extrae IP del atacante desde data.srcip
  4. Conecta via SSH al endpoint afectado
  5. Ejecuta ufw deny para bloquear la IP atacante
  6. Notifica resultado a grupo Telegram ARGOS SOC Alerts

Campos empiricamente validados del JSON de alerta 100101/100103:
  - IP atacante: data.srcip

Ejecucion: servidor Wazuh (.10) como servicio systemd argos-pb02
Autor: ARGOS SOC - Miguel Reguero
"""

import sys
import os
import re
import json
import subprocess
import urllib.request
import urllib.error
from datetime import datetime

# --- Configuracion ---
TELEGRAM_BOT_TOKEN = "***REMOVED***"
TELEGRAM_CHAT_ID = "-5399235712"
ALERTS_JSON = "/var/ossec/logs/alerts/alerts.json"
SSH_KEY = "/var/ossec/.ssh/id_ed25519"
SSH_USER = "argos"

AGENT_IPS = {
    "002": "192.168.234.30",  # ARGOS-Endpoint-Linux
}

TRIGGER_RULES = {"100103"}

LOG_FILE = "/var/ossec/logs/argos_pb02_integration.log"


def log(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] PB02-SSH | {message}"
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


def ssh_execute(endpoint_ip, command):
    try:
        result = subprocess.run(
            [
                "ssh",
                "-i", SSH_KEY,
                "-o", "StrictHostKeyChecking=no",
                "-o", "ConnectTimeout=5",
                f"{SSH_USER}@{endpoint_ip}",
                command
            ],
            capture_output=True, text=True, timeout=15
        )
        return result.returncode == 0, result.stdout.strip(), result.stderr.strip()
    except Exception as e:
        return False, "", str(e)


def block_ip(endpoint_ip, attacker_ip):
    cmd = f"sudo ufw deny from {attacker_ip} to any"
    ok, out, err = ssh_execute(endpoint_ip, cmd)
    if ok:
        log(f"UFW: IP atacante {attacker_ip} bloqueada en {endpoint_ip}")
    else:
        log(f"UFW: ERROR bloqueando {attacker_ip} en {endpoint_ip} - {err}")
    return ok


def parse_alert(line):
    try:
        alert = json.loads(line.strip())
        rule_id = alert.get("rule", {}).get("id", "")
        if rule_id not in TRIGGER_RULES:
            return None

        agent_id = alert.get("agent", {}).get("id", "")
        agent_name = alert.get("agent", {}).get("name", "desconocido")
        level = alert.get("rule", {}).get("level", 0)
        rule_desc = alert.get("rule", {}).get("description", "")

        # IP atacante: campo empiricamente validado data.srcip
        attacker_ip = alert.get("data", {}).get("srcip")

        return {
            "rule_id": rule_id,
            "agent_id": agent_id,
            "agent_name": agent_name,
            "level": level,
            "rule_desc": rule_desc,
            "attacker_ip": attacker_ip,
        }
    except Exception:
        return None


def respond(alert):
    agent_id = alert["agent_id"]
    endpoint_ip = AGENT_IPS.get(agent_id)

    if not endpoint_ip:
        log(f"ERROR: No hay IP mapeada para agent_id {agent_id}. Abortando.")
        return

    log(f"Iniciando contencion en {endpoint_ip} (agente {agent_id})")
    log(f"Regla: {alert['rule_id']} | IP atacante: {alert['attacker_ip']}")

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    acciones = []
    errores = []

    if alert["attacker_ip"]:
        ok = block_ip(endpoint_ip, alert["attacker_ip"])
        if ok:
            acciones.append(f"IP atacante bloqueada: <code>{alert['attacker_ip']}</code>")
        else:
            errores.append(f"Fallo al bloquear IP: {alert['attacker_ip']}")
    else:
        errores.append("IP atacante no disponible en la alerta")

    estado = "CONTENCION APLICADA" if not errores else "CONTENCION PARCIAL - REVISION REQUERIDA"
    emoji = "🔴" if not errores else "🟡"

    mensaje = (
        f"{emoji} <b>ARGOS SOC - PB02 BRUTE FORCE SSH DETECTADO</b>\n\n"
        f"<b>Timestamp:</b> <code>{now}</code>\n"
        f"<b>Agente:</b> <code>{alert['agent_name']}</code> ({endpoint_ip})\n"
        f"<b>Regla:</b> <code>{alert['rule_id']}</code> (nivel {alert['level']})\n"
        f"<b>Descripcion:</b> {alert['rule_desc']}\n\n"
        f"<b>Estado:</b> {estado}\n\n"
    )

    if acciones:
        mensaje += "<b>Acciones ejecutadas:</b>\n"
        for a in acciones:
            mensaje += f"  - {a}\n"

    if errores:
        mensaje += "\n<b>Errores / revision manual requerida:</b>\n"
        for e in errores:
            mensaje += f"  - {e}\n"

    mensaje += "\n<i>ARGOS SOC - Supervision humana requerida para confirmar contencion.</i>"
    send_telegram(mensaje)
    log(f"Contencion finalizada. Estado: {estado}")


def main():
    log("=" * 60)
    log("PB02-SSH Integration iniciado - Monitorizando alerts.json")
    log(f"Triggers: rules {TRIGGER_RULES}")
    log("=" * 60)

    if not os.path.exists(ALERTS_JSON):
        log(f"ERROR: {ALERTS_JSON} no existe. Abortando.")
        sys.exit(1)

    proc = subprocess.Popen(
        ["tail", "-f", "-n", "0", ALERTS_JSON],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    log("Esperando alertas...")

    try:
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            alert = parse_alert(line)
            if alert:
                log(f"Alerta detectada: rule {alert['rule_id']} desde agente {alert['agent_id']}")
                respond(alert)
    except KeyboardInterrupt:
        log("PB02-SSH Integration detenido por el usuario.")
        proc.terminate()


if __name__ == "__main__":
    main()
