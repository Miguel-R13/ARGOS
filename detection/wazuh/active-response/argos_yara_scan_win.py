#!/usr/bin/env python3
# ARGOS SOC - Miguel Reguero
# Active Response: YARA scanner Windows - Wazuh 4.9.2
import sys, json, subprocess, os, datetime

YARA_BIN = "C:\\Program Files (x86)\\ossec-agent\\active-response\\bin\\yara\\yara64.exe"
YARA_RULES = "C:\\argos\\yara\\rules\\windows\\argos_windows_all.yar"
LOG_FILE = "C:\\Program Files (x86)\\ossec-agent\\logs\\active-responses.log"
EVENTS_LOG = "C:\\Program Files (x86)\\ossec-agent\\logs\\argos_yara_events.log"
EXCL_EXT = ['.yar', '.yarc', '.yara']
EXCL_PATHS = ['C:\\argos\\yara', 'C:\\Program Files (x86)\\ossec-agent']

def log(msg):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        open(LOG_FILE,"a").write(f"{ts} argos_yara_scan_win: {msg}\n")
    except: pass

def send(data):
    try:
        ts = datetime.datetime.now().strftime("%b %d %H:%M:%S")
        line = f"{ts} ARGOS-Endpoint-Windows argos_yara_match: {json.dumps(data)}\n"
        open(EVENTS_LOG,"a").write(line)
        log(f"Evento: {json.dumps(data)}")
    except Exception as e: log(f"ERROR: {e}")

def scan(path):
    try:
        r = subprocess.run([YARA_BIN,"-s",YARA_RULES,path],capture_output=True,text=True,timeout=30)
        return r.stdout.strip()
    except Exception as e: log(f"ERROR YARA: {e}"); return ""

def main():
    try:
        ev = json.loads(sys.stdin.readline().rstrip())
    except Exception as e: log(f"ERROR input: {e}"); sys.exit(1)
    if ev.get("command","") != "add": sys.exit(0)
    try: path = ev["parameters"]["alert"]["syscheck"]["path"]
    except: log("No path"); sys.exit(0)
    if not path or not os.path.isfile(path): log(f"Not found: {path}"); sys.exit(0)
    if os.path.splitext(path)[1].lower() in EXCL_EXT: log(f"Excluido ext: {path}"); sys.exit(0)
    if any(path.lower().startswith(p.lower()) for p in EXCL_PATHS): log(f"Excluido ruta: {path}"); sys.exit(0)
    log(f"Escaneando: {path}")
    out = scan(path)
    if not out: log(f"Sin match: {path}"); sys.exit(0)
    rules = list(set([l.split()[0] for l in out.split("\n") if l and not l.startswith("0x")]))
    for r in rules:
        send({"yara_rule":r,"yara_file":path,"integration":"argos_yara"})
        log(f"MATCH: {r} en {path}")

if __name__ == "__main__": main()
