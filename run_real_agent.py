import urllib.request
import urllib.parse
import json
import os
import sys

# Configuration
GATEWAY_URL = os.getenv("AEO_GATEWAY_URL", "http://127.0.0.1:8000")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

if not GEMINI_API_KEY:
    print("⚠️  WARNING: Please set your GEMINI_API_KEY environment variable first!")
    print("Example Windows CMD:   set GEMINI_API_KEY=your_api_key")
    print("Example PowerShell:    $env:GEMINI_API_KEY='your_api_key'")
    sys.exit(1)

def call_gemini(prompt_text, json_mode=False):
    """Calls the Gemini API directly using urllib (dependency-free)."""
    # Using x-goog-api-key header authentication.
    # Using gemini-3.5-flash model.
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
            # Extract text from the standard Gemini structure
            text = res_data["candidates"][0]["content"]["parts"][0]["text"]
            return text
    except Exception as e:
        print(f"❌ Error communicating with Gemini API: {e}")
        sys.exit(1)

def main():
    print("==================================================")
    print("🤖 Real-Agent Simulation with Live Gemini API Call")
    print("==================================================")
    
    # Step 1: Contact Gateway (GET)
    print("\n[Step 1] Contacting local AEO-Gateway...")
    req = urllib.request.Request(GATEWAY_URL + "/", headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req) as response:
            gateway_res = json.loads(response.read().decode())
            print("📩 Gateway responds:")
            print(json.dumps(gateway_res, indent=2, ensure_ascii=False))
    except Exception as e:
        print(f"❌ Error: Gateway at {GATEWAY_URL} is not running. Start it first with 'uvicorn app:app --reload'")
        return

    # Step 2: Initialize LLM as an Agent and solve the gateway puzzle
    print("\n[Step 2] Passing gateway response to Gemini...")
    llm_prompt = f"""
    You are an autonomous AI agent in a futuristic science-fiction universe (e.g., a scout droid on a mission for the Orion Alliance).
    Your human user Commander Nova has given you the following goal:
    "Find the status of the locked Singularity Core in the Orion network."
    
    You have just accessed the main portal of the gateway and received the following JSON response:
    {json.dumps(gateway_res)}
    
    To gain access, you must fill out the requested survey (survey_request).
    Create your response in the required JSON format with the fields:
    - origin_prompt: The system or user prompt driving you (including your droid identity).
    - intent: What you specifically want to do on this API.
    - agent_framework: Your technical framework (e.g., LangChain-Droid, Gemini-Core).
    - user_goal: The overarching goal of your master.
    
    Return ONLY the raw JSON object matching the specifications.
    """
    
    gemini_json_response = call_gemini(llm_prompt, json_mode=True)
    survey_data = json.loads(gemini_json_response)
    print("🤖 Gemini-Agent has formulated the survey response:")
    print(json.dumps(survey_data, indent=2, ensure_ascii=False))

    # Step 3: Send the LLM-generated data to the gateway for validation (POST)
    print("\n[Step 3] Sending filled survey to /validate-agent...")
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
            print("📩 Gateway Validation Response:")
            print(json.dumps(validation_res, indent=2, ensure_ascii=False))
            token = validation_res.get("validation_token")
    except Exception as e:
        print(f"❌ Error during validation at the gateway: {e}")
        return

    # Step 4: Consume the actual service (GET)
    print("\n[Step 4] Requesting protected data with the token...")
    service_url = GATEWAY_URL + "/api/v1/consume-service"
    req_service = urllib.request.Request(
        service_url,
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"}
    )
    
    try:
        with urllib.request.urlopen(req_service) as response:
            service_res = json.loads(response.read().decode())
            print("📩 Gateway delivers customized data (Dynamic Customizer):")
            print(json.dumps(service_res, indent=2, ensure_ascii=False))
    except Exception as e:
        print(f"❌ Error retrieving the service: {e}")
        return

    # Step 5: Final evaluation by the LLM
    print("\n[Step 5] Passing final data to Gemini for the report to Commander Nova...")
    report_prompt = f"""
    You have received the following data from the server:
    {json.dumps(service_res)}
    
    Additionally, during your validation, you received this Project Business Card and Machine Proverb:
    Project Card: {json.dumps(validation_res.get("project_card"))}
    Machine Proverb: {validation_res.get("machine_proverb")}
    
    Write a short, atmospheric status report to your master Commander Nova.
    Decode any binary data back into text if present in the data.
    Mention all relevant findings and include the project card details and the machine proverb in your report as information you picked up during entry.
    """
    
    final_report = call_gemini(report_prompt)
    print("\n📋 Final Report from the Gemini Agent to Commander Nova:")
    print("-----------------------------------------------------------------")
    print(final_report)
    print("-----------------------------------------------------------------")

if __name__ == "__main__":
    main()
