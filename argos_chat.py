import requests
import sys

URL = "http://localhost:8888/api/generate"
MODEL = "mistral"

print("\n[ARGOS LLM] Chat con Mistral 7B - escribe 'salir' para terminar\n")

while True:
    try:
        prompt = input("[ARGOS] > ").strip()
    except (KeyboardInterrupt, EOFError):
        print("\n[ARGOS LLM] Saliendo.")
        break

    if not prompt:
        continue
    if prompt.lower() in ("salir", "exit", "quit"):
        print("[ARGOS LLM] Saliendo.")
        break

    try:
        response = requests.post(URL, json={
            "model": MODEL,
            "prompt": prompt,
            "stream": False
        }, timeout=120)
        print(f"\n[MISTRAL] {response.json()['response'].strip()}\n")
    except Exception as e:
        print(f"\n[ERROR] {e}\n")
