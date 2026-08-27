#!/usr/bin/env python3
"""
ARGOS SOC - PB04 Exfiltracion de datos - Integration Script (servidor .10)
Monitoriza alerts.json en tiempo real, detecta rule 100801 (exfiltracion Linux confirmada)
y ejecuta contencion activa via SSH en el endpoint Linux afectado.

Flujo:
  1. Lee alerts.json en tiempo real (tail -f)
  2. Filtra alertas de rule 100801 desde agente 002 (ARGOS-Endpoint-Linux)
  3. Extrae IP destino del full_log (SOCKADDR laddr) y PID de data.audit.pid
  4. Conecta via SSH al endpoint afectado
  5. Ejecuta kill -9 (terminar proceso) y ufw deny (bloquear IP destino)
  6. Notifica resultado a grupo Telegram ARGOS SOC Alerts

Campos empiricamente validados del JSON de alerta 100801:
  - IP destino: regex laddr=IP sobre full_log (SOCKADDR inet)
  - PID: data.audit.pid

Ejecucion: servidor Wazuh (.10) como servicio systemd argos-pb04
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
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = "-5399235712"
ALERTS_JSON = "/var/ossec/logs/alerts/alerts.json"
SSH_KEY = "/var/ossec/.ssh/id_ed25519"
SSH_USER = "argos"

AGENT_IPS = {
    "002": "192.168.234.30",  # ARGOS-Endpoint-Linux
}

TRIGGER_RULES = {"100801"}

LOG_FILE = "/var/ossec/logs/argos_pb04_integration.log"


def log(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] PB04-EXFIL | {message}"
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


def kill_process(endpoint_ip, pid):
    cmd = f"sudo kill -9 {pid}"
    ok, out, err = ssh_execute(endpoint_ip, cmd)
    if ok:
        log(f"KILL: PID {pid} terminado en {endpoint_ip}")
    else:
        log(f"KILL: ERROR terminando PID {pid} en {endpoint_ip} - {err}")
    return ok


def block_ip(endpoint_ip, dest_ip):
    cmd = f"sudo ufw deny from {dest_ip} to any"
    ok, out, err = ssh_execute(endpoint_ip, cmd)
    if ok:
        log(f"UFW: IP destino {dest_ip} bloqueada en {endpoint_ip}")
    else:
        log(f"UFW: ERROR bloqueando {dest_ip} en {endpoint_ip} - {err}")
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
        full_log = alert.get("full_log", "")

        # IP destino: extraer del SOCKADDR inet del full_log
        # Solo el SOCKADDR con saddr_fam=inet tiene laddr con IP real
        dest_ip = None
        match = re.search(r"saddr_fam=inet laddr=([\d.]+)", full_log)
        if match:
            dest_ip = match.group(1)

        # PID: campo empiricamente validado data.audit.pid
        pid = alert.get("data", {}).get("audit", {}).get("pid")

        # Exe: para el log
        exe = alert.get("data", {}).get("audit", {}).get("exe", "desconocido")

        return {
            "rule_id": rule_id,
            "agent_id": agent_id,
            "agent_name": agent_name,
            "level": level,
            "rule_desc": rule_desc,
            "dest_ip": dest_ip,
            "pid": pid,
            "exe": exe,
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
    log(f"Regla: {alert['rule_id']} | Exe: {alert['exe']} | IP destino: {alert['dest_ip']} | PID: {alert['pid']}")

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    acciones = []
    errores = []

    # Accion 1: Matar proceso
    if alert["pid"]:
        ok = kill_process(endpoint_ip, alert["pid"])
        if ok:
            acciones.append(f"Proceso terminado: PID <code>{alert['pid']}</code> ({alert['exe']})")
        else:
            errores.append(f"Fallo al terminar PID: {alert['pid']}")
    else:
        errores.append("PID no disponible en la alerta")

    # Accion 2: Bloquear IP destino
    if alert["dest_ip"]:
        ok = block_ip(endpoint_ip, alert["dest_ip"])
        if ok:
            acciones.append(f"IP destino bloqueada: <code>{alert['dest_ip']}</code>")
        else:
            errores.append(f"Fallo al bloquear IP destino: {alert['dest_ip']}")
    else:
        errores.append("IP destino no disponible en la alerta")

    estado = "CONTENCION APLICADA" if not errores else "CONTENCION PARCIAL - REVISION REQUERIDA"
    emoji = "🔴" if not errores else "🟡"

    mensaje = (
        f"{emoji} <b>ARGOS SOC - PB04 EXFILTRACION DE DATOS DETECTADA (LINUX)</b>\n\n"
        f"<b>Timestamp:</b> <code>{now}</code>\n"
        f"<b>Agente:</b> <code>{alert['agent_name']}</code> ({endpoint_ip})\n"
        f"<b>Regla:</b> <code>{alert['rule_id']}</code> (nivel {alert['level']})\n"
        f"<b>Proceso:</b> <code>{alert['exe']}</code>\n\n"
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
    log("PB04-EXFIL Integration iniciado - Monitorizando alerts.json")
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
        log("PB04-EXFIL Integration detenido por el usuario.")
        proc.terminate()


if __name__ == "__main__":
    main()
