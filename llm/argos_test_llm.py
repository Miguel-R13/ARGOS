import requests

url = "http://localhost:8888/api/generate"

payload = {
    "model": "mistral",
    "prompt": "Responde en una frase: ¿qué es un SOC?",
    "stream": False
}

response = requests.post(url, json=payload)
resultado = response.json()["response"].strip()

print("\n[ARGOS LLM] Pregunta: ¿qué es un SOC?")
print(f"[ARGOS LLM] Respuesta: {resultado}\n")
