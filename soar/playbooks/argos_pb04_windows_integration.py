#!/usr/bin/env python3
"""
ARGOS SOC - PB04 Exfiltracion de datos - Integration Script Windows (servidor .10)
Monitoriza alerts.json en tiempo real, detecta rule 102003 (exfiltracion Windows confirmada)
y ejecuta contencion activa via WinRM en el endpoint Windows afectado.

Flujo:
  1. Lee alerts.json en tiempo real (tail -f)
  2. Filtra alertas de rule 102003 desde agente 001 (ARGOS-Endpoint-Windows)
  3. Extrae PID del proceso desde data.win.eventdata.processId
  4. Conecta via WinRM al endpoint afectado
  5. Ejecuta Stop-Process para terminar el proceso de exfiltracion
  6. Notifica resultado a grupo Telegram ARGOS SOC Alerts

Campos empiricamente validados del JSON de alerta 102000/102003:
  - PID: data.win.eventdata.processId
  - Imagen: data.win.eventdata.image
  - CommandLine: data.win.eventdata.commandLine

Ejecucion: servidor Wazuh (.10) como servicio systemd argos-pb04-windows
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
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = "-5399235712"
ALERTS_JSON = "/var/ossec/logs/alerts/alerts.json"

WINRM_USER = "Analista"
WINRM_PASS = "Analista"

AGENT_IPS = {
    "001": "192.168.234.20",  # ARGOS-Endpoint-Windows
}

TRIGGER_RULES = {"102003"}

LOG_FILE = "/var/ossec/logs/argos_pb04_windows_integration.log"


def log(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] PB04-WINDOWS | {message}"
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


def kill_process(endpoint_ip, pid):
    cmd = f"Stop-Process -Id {pid} -Force -ErrorAction SilentlyContinue; Write-Output ok"
    ok, out = winrm_execute(endpoint_ip, cmd)
    if ok and "ok" in out:
        log(f"KILL: PID {pid} terminado en {endpoint_ip}")
        return True
    else:
        log(f"KILL: ERROR terminando PID {pid} en {endpoint_ip} - {out}")
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

        # PID: campo empiricamente validado data.win.eventdata.processId
        pid = (
            alert.get("data", {})
                 .get("win", {})
                 .get("eventdata", {})
                 .get("processId")
        )

        # Imagen del proceso
        image = (
            alert.get("data", {})
                 .get("win", {})
                 .get("eventdata", {})
                 .get("image", "desconocido")
        )

        # CommandLine para contexto
        cmdline = (
            alert.get("data", {})
                 .get("win", {})
                 .get("eventdata", {})
                 .get("commandLine", "")
        )

        return {
            "rule_id": rule_id,
            "agent_id": agent_id,
            "agent_name": agent_name,
            "level": level,
            "rule_desc": rule_desc,
            "pid": pid,
            "image": image,
            "cmdline": cmdline,
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
    log(f"Regla: {alert['rule_id']} | Proceso: {alert['image']} | PID: {alert['pid']}")

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    acciones = []
    errores = []

    if alert["pid"]:
        ok = kill_process(endpoint_ip, alert["pid"])
        if ok:
            acciones.append(f"Proceso terminado: PID <code>{alert['pid']}</code> ({alert['image']})")
        else:
            errores.append(f"Fallo al terminar PID: {alert['pid']}")
    else:
        errores.append("PID no disponible en la alerta")

    estado = "CONTENCION APLICADA" if not errores else "CONTENCION PARCIAL - REVISION REQUERIDA"
    emoji = "🔴" if not errores else "🟡"

    mensaje = (
        f"{emoji} <b>ARGOS SOC - PB04 EXFILTRACION DE DATOS DETECTADA (WINDOWS)</b>\n\n"
        f"<b>Timestamp:</b> <code>{now}</code>\n"
        f"<b>Agente:</b> <code>{alert['agent_name']}</code> ({endpoint_ip})\n"
        f"<b>Regla:</b> <code>{alert['rule_id']}</code> (nivel {alert['level']})\n"
        f"<b>Proceso:</b> <code>{alert['image']}</code>\n"
        f"<b>Comando:</b> <code>{alert['cmdline'][:100]}</code>\n\n"
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
    log("PB04-WINDOWS Integration iniciado - Monitorizando alerts.json")
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
        log("PB04-WINDOWS Integration detenido por el usuario.")
        proc.terminate()


if __name__ == "__main__":
    main()
