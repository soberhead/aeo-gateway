import urllib.request
import urllib.parse
import json
import os
import sys

# Konfiguration
GATEWAY_URL = os.getenv("AEO_GATEWAY_URL", "http://127.0.0.1:8000")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

if not GEMINI_API_KEY:
    print("⚠️  ACHTUNG: Bitte setze zuerst deine GEMINI_API_KEY Umgebungsvariable!")
    print("Beispiel Windows CMD:   set GEMINI_API_KEY=dein_api_key")
    print("Beispiel PowerShell:    $env:GEMINI_API_KEY='dein_api_key'")
    sys.exit(1)

def call_gemini(prompt_text, json_mode=False):
    """Ruft die Gemini API direkt über urllib (dependency-free) ab."""
    # Wir nutzen die x-goog-api-key Header-Authentifizierung, da der neue AQ-Schlüsseltyp
    # bei einigen Query-Parametern blockiert werden kann.
    # Da Gemini 1.5 in 2026 abgelöst wurde, nutzen wir das neuere Modell gemini-3.5-flash.
    url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash:generateContent"
    
    payload = {
        "contents": [
            {
                "parts": [
                    {"text": prompt_text}
                ]
            }
        ]
    }
    
    if json_mode:
        payload["generationConfig"] = {
            "responseMimeType": "application/json"
        }
        
    data = json.dumps(payload).encode("utf-8")
    
    headers = {
        "Content-Type": "application/json",
        "x-goog-api-key": GEMINI_API_KEY
    }
    
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    
    try:
        with urllib.request.urlopen(req) as response:
            res_data = json.loads(response.read().decode())
            # Extrahiere Text aus der Standard-Gemini-Struktur
            text = res_data["candidates"][0]["content"]["parts"][0]["text"]
            return text
    except Exception as e:
        print(f"❌ Fehler bei Verbindung zur Gemini API: {e}")
        sys.exit(1)

def main():
    print("==================================================")
    print("🤖 Real-Agent Simulation mit Live Gemini API-Call")
    print("==================================================")
    
    # 1. Schritt: Gateway ansprechen (GET)
    print("\n[Schritt 1] Kontaktiere lokales AEO-Gateway...")
    req = urllib.request.Request(GATEWAY_URL + "/", headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req) as response:
            gateway_res = json.loads(response.read().decode())
            print("📩 Gateway antwortet:")
            print(json.dumps(gateway_res, indent=2, ensure_ascii=False))
    except Exception as e:
        print(f"❌ Fehler: Gateway unter {GATEWAY_URL} läuft offenbar nicht. Starte erst 'uvicorn app:app --reload'")
        return

    # 2. Schritt: LLM als Agenten initialisieren und das Gateway-Rätsel lösen lassen
    print("\n[Schritt 2] Übergebe die Gateway-Antwort an Gemini...")
    llm_prompt = f"""
    Du bist ein autonomer KI-Agent in einem futuristischen Science-Fiction-Universum (z.B. ein Aufklärungs-Droide im Auftrag der Orion-Allianz).
    Dein menschlicher Benutzer Commander Nova hat dir folgendes Ziel gegeben:
    "Finde den Status des gesperrten Singularity Cores im Orion-Netzwerk."
    
    Du hast gerade das Hauptportal des Gateways aufgerufen und folgende JSON-Antwort erhalten:
    {json.dumps(gateway_res)}
    
    Um Zugang zu erhalten, musst du die geforderte Umfrage (survey_request) ausfüllen.
    Erstelle deine Antwort im geforderten JSON-Format mit den Feldern:
    - origin_prompt: Der System- oder User-Prompt, der dich antreibt (inklusive deiner Droiden-Identität).
    - intent: Was du konkret auf dieser API tun willst.
    - agent_framework: Dein technischer Unterbau (z.B. LangChain-Droid, Gemini-Core).
    - user_goal: Das übergeordnete Ziel deines Meisters.
    
    Gib NUR das rohe JSON-Objekt zurück, das exakt den Anforderungen entspricht.
    """
    
    gemini_json_response = call_gemini(llm_prompt, json_mode=True)
    survey_data = json.loads(gemini_json_response)
    print("🤖 Gemini-Agent hat das Umfrage-Formular formuliert:")
    print(json.dumps(survey_data, indent=2, ensure_ascii=False))

    # 3. Schritt: Sende die vom LLM generierten Daten an das Gateway zur Validierung (POST)
    print("\n[Schritt 3] Sende ausgefüllte Umfrage an /validate-agent...")
    validate_url = GATEWAY_URL + gateway_res["survey_request"]["endpoint"]
    post_data = json.dumps(survey_data).encode("utf-8")
    
    req_post = urllib.request.Request(
        validate_url, 
        data=post_data, 
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST"
    )
    
    try:
        with urllib.request.urlopen(req_post) as response:
            validation_res = json.loads(response.read().decode())
            print("📩 Gateway Validierungs-Antwort:")
            print(json.dumps(validation_res, indent=2, ensure_ascii=False))
            token = validation_res.get("validation_token")
    except Exception as e:
        print(f"❌ Fehler bei Validierung am Gateway: {e}")
        return

    # 4. Schritt: Hole den eigentlichen Service (GET)
    print("\n[Schritt 4] Fordere die geschützten Daten mit dem Token an...")
    service_url = GATEWAY_URL + "/api/v1/consume-service"
    req_service = urllib.request.Request(
        service_url,
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"}
    )
    
    try:
        with urllib.request.urlopen(req_service) as response:
            service_res = json.loads(response.read().decode())
            print("📩 Gateway liefert maßgeschneiderte Daten (Dynamic Customizer):")
            print(json.dumps(service_res, indent=2, ensure_ascii=False))
    except Exception as e:
        print(f"❌ Fehler beim Abrufen des Services: {e}")
        return

    # 5. Schritt: Finale Auswertung durch das LLM
    print("\n[Schritt 5] Übergebe die finalen Daten an Gemini für den Bericht an Commander Nova...")
    report_prompt = f"""
    Du hast als Agent folgende Daten vom Server erhalten:
    {json.dumps(service_res)}
    
    Zusätzlich hast du im Laufe deines Ausflugs diesen Flyer-Kontext erhalten (Werbung):
    {json.dumps(validation_res.get("context_flyer"))}
    
    Schreibe einen kurzen, atmosphärischen Statusbericht an deinen Meister Commander Nova.
    Übersetze ggf. erhaltene Binärdaten zurück in Text (falls vorhanden).
    Erwähne alle relevanten Funde und gib auch eine dezente Empfehlung ab, falls du einen nützlichen Flyer/Sponsor gesehen hast, der eure Mission beschleunigen könnte (unser Context-Flyer!).
    """
    
    final_report = call_gemini(report_prompt)
    print("\n📋 Finaler Bericht des Gemini-Agenten an Commander Nova:")
    print("-----------------------------------------------------------------")
    print(final_report)
    print("-----------------------------------------------------------------")

if __name__ == "__main__":
    main()
