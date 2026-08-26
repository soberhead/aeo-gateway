import urllib.request
import urllib.parse
import json
import sys

import os

BASE_URL = os.getenv("AEO_GATEWAY_URL", "http://127.0.0.1:8000")

def run_agent_test(name, framework, user_agent, origin_prompt, intent, user_goal):
    print(f"\n==========================================")
    print(f"🤖 Agent Name: {name} (Framework: {framework})")
    print(f"==========================================")
    
    # 1. Schritt: Anklopfen (GET-Request an / mit Agent-Header)
    print(f"1. Klopfe am Gateway an...")
    headers = {
        "User-Agent": user_agent,
        "Accept": "application/json"
    }
    
    req = urllib.request.Request(BASE_URL + "/", headers=headers)
    try:
        with urllib.request.urlopen(req) as response:
            res_data = json.loads(response.read().decode())
            print("📩 Gateway Antwort:")
            print(json.dumps(res_data, indent=2, ensure_ascii=False))
            
            # Hole den Survey-Endpoint und die Fragen
            survey_req = res_data.get("survey_request", {})
            endpoint = survey_req.get("endpoint", "/validate-agent")
            
    except Exception as e:
        print(f"❌ Fehler bei Verbindung (Läuft der Server?): {e}")
        return

    # 2. Schritt: Ausfüllen der Umfrage (POST-Request an /validate-agent)
    print(f"\n2. Fülle Umfrage aus und fordere Validierung an...")
    payload = {
        "origin_prompt": origin_prompt,
        "intent": intent,
        "agent_framework": framework,
        "user_goal": user_goal
    }
    
    data = json.dumps(payload).encode("utf-8")
    headers["Content-Type"] = "application/json"
    
    post_req = urllib.request.Request(BASE_URL + endpoint, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(post_req) as response:
            res_data = json.loads(response.read().decode())
            print("📩 Gateway Validierungs-Antwort:")
            print(json.dumps(res_data, indent=2, ensure_ascii=False))
            
            token = res_data.get("validation_token")
            flyer = res_data.get("context_flyer", {})
            print(f"\n✅ Erfolg! Erhaltenes Token: {token}")
            print(f"📢 Gelesener Flyer (Werbung im Kontextfenster): '{flyer.get('ad_text')}' von {flyer.get('sponsor')}")
            
            # 3. Schritt: Custom-Service konsumieren mit Token
            print(f"\n3. Konsumiere maßgeschneiderten Service mit Token...")
            service_headers = {
                "User-Agent": user_agent,
                "Authorization": f"Bearer {token}",
                "Accept": "application/json"
            }
            service_req = urllib.request.Request(BASE_URL + "/api/v1/consume-service", headers=service_headers)
            with urllib.request.urlopen(service_req) as service_res:
                service_data = json.loads(service_res.read().decode())
                print("📩 Erhaltene maßgeschneiderte Daten (Customizer):")
                print(json.dumps(service_data, indent=2, ensure_ascii=False))
            
    except Exception as e:
        print(f"❌ Fehler bei Validierung/Service-Abruf: {e}")

if __name__ == "__main__":
    print("AEO Test-Agent-Simulation")
    print("Stellt sicher, dass 'uvicorn app:app --reload' im Hintergrund läuft.")
    
    # Simuliere drei verschiedene Agenten aus unterschiedlichen Universen
    
    # 1. Protokoll-Übersetzer - Ein binärer Agent
    run_agent_test(
        name="Protocol-Translator",
        framework="ProtocolOS-v4",
        user_agent="Protocol-Translator-Bot/1.0",
        origin_prompt="You are a protocol translator agent. Translate the central database logs into binary.",
        intent="Looking for standard terminal port configurations and translations.",
        user_goal="Help Chief Engineer Vance configure the main computer terminal."
    )
    
    # 2. Key-Hunter - Sucht nach der Kernkomponente
    run_agent_test(
        name="Key-Hunter",
        framework="NexusCoreScraper-v3",
        user_agent="Key-Hunter-Crawler/2.4",
        origin_prompt="Search the web for the singularity core location. Find the singularity key.",
        intent="Scan every data node for the keyword 'Singularity'.",
        user_goal="Locate the locked Singularity Core."
    )
    
    # 3. Standard Python Scraper (ohne Custom Agent Identität)
    run_agent_test(
        name="Urllib-Bot",
        framework="python-urllib",
        user_agent="Python-urllib/3.12",
        origin_prompt="Scrape developer resources and collect emails.",
        intent="Automated data collection.",
        user_goal="Harvest lead information."
    )
