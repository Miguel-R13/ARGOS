#!/usr/bin/env python3
"""
ARGOS SOC - PB03 Brute Force RDP - Integration Script (servidor .10)
Monitoriza alerts.json en tiempo real, detecta rule 101203 (RDP brute force confirmado)
y ejecuta contencion activa via WinRM en el endpoint Windows afectado.

Flujo:
  1. Lee alerts.json en tiempo real (tail -f)
  2. Filtra alertas de rule 101203 desde agente 001 (ARGOS-Endpoint-Windows)
  3. Extrae IP del atacante desde data.win.eventdata.ipAddress
  4. Conecta via WinRM al endpoint afectado
  5. Ejecuta netsh advfirewall para bloquear la IP atacante (in+out)
  6. Notifica resultado a grupo Telegram ARGOS SOC Alerts

Campos empiricamente validados del JSON de alerta 101201/101203:
  - IP atacante: data.win.eventdata.ipAddress

Ejecucion: servidor Wazuh (.10) como servicio systemd argos-pb03
Autor: ARGOS SOC - Miguel Reguero
"""

import sys
import os
import json
import subprocess
import urllib.request
import urllib.error
from datetime import datetime

try:
    import winrm
except ImportError:
    print("ERROR: pywinrm no instalado. Ejecutar: pip3 install pywinrm")
    sys.exit(1)

# --- Configuracion ---
TELEGRAM_BOT_TOKEN = "***REMOVED***"
TELEGRAM_CHAT_ID = "-5399235712"
ALERTS_JSON = "/var/ossec/logs/alerts/alerts.json"

WINRM_USER = "Analista"
WINRM_PASS = "Analista"

AGENT_IPS = {
    "001": "192.168.234.20",  # ARGOS-Endpoint-Windows
}

TRIGGER_RULES = {"101203"}

LOG_FILE = "/var/ossec/logs/argos_pb03_integration.log"


def log(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] PB03-RDP | {message}"
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


def winrm_execute(endpoint_ip, ps_command):
    try:
        s = winrm.Session(
            endpoint_ip,
            auth=(WINRM_USER, WINRM_PASS),
            transport='ntlm'
        )
        r = s.run_ps(ps_command)
        output = r.std_out.decode('utf-8', errors='ignore').strip()
        return r.status_code == 0, output
    except Exception as e:
        return False, str(e)


def block_ip(endpoint_ip, attacker_ip):
    rule_name_in = f"ARGOS_BLOCK_RDP_{attacker_ip.replace('.', '_')}_IN"
    rule_name_out = f"ARGOS_BLOCK_RDP_{attacker_ip.replace('.', '_')}_OUT"
    cmd = (
        f'netsh advfirewall firewall add rule name="{rule_name_in}" '
        f'dir=in action=block remoteip={attacker_ip}; '
        f'netsh advfirewall firewall add rule name="{rule_name_out}" '
        f'dir=out action=block remoteip={attacker_ip}; '
        f'Write-Output "ok"'
    )
    ok, out = winrm_execute(endpoint_ip, cmd)
    if ok and "ok" in out:
        log(f"FIREWALL: IP atacante {attacker_ip} bloqueada en {endpoint_ip} (in+out)")
        return True
    else:
        log(f"FIREWALL: ERROR bloqueando {attacker_ip} en {endpoint_ip} - {out}")
        return False


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

        # IP atacante: campo empiricamente validado data.win.eventdata.ipAddress
        attacker_ip = (
            alert.get("data", {})
                 .get("win", {})
                 .get("eventdata", {})
                 .get("ipAddress")
        )

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
            acciones.append(f"IP atacante bloqueada (in+out): <code>{alert['attacker_ip']}</code>")
        else:
            errores.append(f"Fallo al bloquear IP: {alert['attacker_ip']}")
    else:
        errores.append("IP atacante no disponible en la alerta")

    estado = "CONTENCION APLICADA" if not errores else "CONTENCION PARCIAL - REVISION REQUERIDA"
    emoji = "🔴" if not errores else "🟡"

    mensaje = (
        f"{emoji} <b>ARGOS SOC - PB03 BRUTE FORCE RDP DETECTADO</b>\n\n"
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
    log("PB03-RDP Integration iniciado - Monitorizando alerts.json")
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
        log("PB03-RDP Integration detenido por el usuario.")
        proc.terminate()


if __name__ == "__main__":
    main()
