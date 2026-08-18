#!/usr/bin/env python3
# ARGOS SOC - Miguel Reguero
# Active Response: YARA scanner para deteccion de artefactos maliciosos
# Wazuh 4.9.2 - envia eventos via localfile a logcollector
# v2: exclusiones de ruido (archivos .yarc, .ko, .yar y rutas de kernel)

import sys
import json
import subprocess
import os
import datetime
import socket

YARA_RULES_PATH = "/opt/argos/yara/rules/linux/argos_linux_all.yar"
LOG_FILE = "/var/ossec/logs/active-responses.log"
YARA_EVENTS_LOG = "/var/ossec/logs/argos_yara_events.log"

# Exclusiones de ruido documentadas en Cap13 - Reduccion de ruido ARGOS
EXCLUDED_EXTENSIONS = ['.yarc', '.ko', '.yar']
EXCLUDED_PATHS = ['/var/tmp/mkinitramfs', '/opt/argos/yara']

def log(msg):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"{timestamp} argos_yara_scan: {msg}\n")

def send_to_wazuh(data):
    """Escribe el evento en el log que logcollector envia al servidor."""
    try:
        timestamp = datetime.datetime.now().strftime("%b %d %H:%M:%S")
        msg = json.dumps(data)
        line = f"{timestamp} argos-endpoint-linux argos_yara_match: {msg}\n"
        with open(YARA_EVENTS_LOG, "a") as f:
            f.write(line)
        log(f"Evento escrito en log: {msg}")
    except Exception as e:
        log(f"ERROR escribiendo evento: {e}")

def run_yara(file_path):
    try:
        result = subprocess.run(
            ["yara", "-s", YARA_RULES_PATH, file_path],
            capture_output=True,
            text=True,
            timeout=30
        )
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        log(f"TIMEOUT escaneando {file_path}")
        return ""
    except Exception as e:
        log(f"ERROR ejecutando YARA: {e}")
        return ""

def main():
    try:
        input_str = sys.stdin.readline().rstrip()
        if not input_str:
            log("No input received from Wazuh")
            sys.exit(0)
        event = json.loads(input_str)
    except Exception as e:
        log(f"ERROR leyendo evento: {e}")
        sys.exit(1)

    command = event.get("command", "")
    if command != "add":
        sys.exit(0)

    try:
        file_path = event["parameters"]["alert"]["syscheck"]["path"]
    except (KeyError, TypeError):
        log(f"No se encontro syscheck.path en el evento")
        sys.exit(0)

    if not file_path or not os.path.isfile(file_path):
        log(f"Archivo no encontrado: {file_path}")
        sys.exit(0)

    # Exclusiones de ruido: extensiones y rutas conocidas sin valor SOC
    if any(file_path.endswith(ext) for ext in EXCLUDED_EXTENSIONS):
        log(f"Excluido por extension: {file_path}")
        sys.exit(0)

    if any(file_path.startswith(path) for path in EXCLUDED_PATHS):
        log(f"Excluido por ruta: {file_path}")
        sys.exit(0)

    log(f"Escaneando: {file_path}")

    output = run_yara(file_path)

    if not output:
        log(f"Sin match YARA en: {file_path}")
        sys.exit(0)

    matched_rules = []
    for line in output.split("\n"):
        if line and not line.startswith("0x"):
            parts = line.split(" ")
            if parts:
                matched_rules.append(parts[0])

    matched_rules = list(set(matched_rules))

    for rule in matched_rules:
        alert = {
            "yara_rule": rule,
            "yara_file": file_path,
            "integration": "argos_yara"
        }
        send_to_wazuh(alert)
        log(f"YARA_MATCH: {rule} en {file_path}")

    sys.exit(0)

if __name__ == "__main__":
    main()
