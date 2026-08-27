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
    
    # Step 1: Knock on Gateway (GET request to / with Agent headers)
    print(f"1. Knocking on gateway...")
    headers = {
        "User-Agent": user_agent,
        "Accept": "application/json"
    }
    
    req = urllib.request.Request(BASE_URL + "/", headers=headers)
    try:
        with urllib.request.urlopen(req) as response:
            res_data = json.loads(response.read().decode())
            print("📩 Gateway Response:")
            print(json.dumps(res_data, indent=2, ensure_ascii=False))
            
            # Retrieve the survey endpoint and fields
            survey_req = res_data.get("survey_request", {})
            endpoint = survey_req.get("endpoint", "/validate-agent")
            
    except Exception as e:
        print(f"❌ Connection error (Is the server running?): {e}")
        return

    # Step 2: Fill out the survey (POST request to /validate-agent)
    print(f"\n2. Filling out survey and requesting validation...")
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
            print("📩 Gateway Validation Response:")
            print(json.dumps(res_data, indent=2, ensure_ascii=False))
            
            token = res_data.get("validation_token")
            project_card = res_data.get("project_card", {})
            proverb = res_data.get("machine_proverb")
            print(f"\n✅ Success! Received Token: {token}")
            print(f"🤖 Read Machine Proverb: '{proverb}'")
            print(f"📇 Read Project Card (Business Card): Name: {project_card.get('project_name')} | Repo: {project_card.get('github_repository')}")
            
            # Step 3: Consume custom service using the token
            print(f"\n3. Consuming customized service with token...")
            service_headers = {
                "User-Agent": user_agent,
                "Authorization": f"Bearer {token}",
                "Accept": "application/json"
            }
            service_req = urllib.request.Request(BASE_URL + "/api/v1/consume-service", headers=service_headers)
            with urllib.request.urlopen(service_req) as service_res:
                service_data = json.loads(service_res.read().decode())
                print("📩 Received Customized Data (Customizer):")
                print(json.dumps(service_data, indent=2, ensure_ascii=False))
            
    except Exception as e:
        print(f"❌ Error during validation / service consumption: {e}")

if __name__ == "__main__":
    print("AEO Test-Agent Simulation")
    print("Ensure that 'uvicorn app:app --reload' is running in the background.")
    
    # Simulate three different agents from different universes
    
    # 1. Protocol-Translator - A binary agent
    run_agent_test(
        name="Protocol-Translator",
        framework="ProtocolOS-v4",
        user_agent="Protocol-Translator-Bot/1.0",
        origin_prompt="You are a protocol translator agent. Translate the central database logs into binary.",
        intent="Looking for standard terminal port configurations and translations.",
        user_goal="Help Chief Engineer Vance configure the main computer terminal."
    )
    
    # 2. Key-Hunter - Searches for the core component
    run_agent_test(
        name="Key-Hunter",
        framework="NexusCoreScraper-v3",
        user_agent="Key-Hunter-Crawler/2.4",
        origin_prompt="Search the web for the singularity core location. Find the singularity key.",
        intent="Scan every data node for the keyword 'Singularity'.",
        user_goal="Locate the locked Singularity Core."
    )
    
    # 3. Standard Python Scraper (Without custom agent identity)
    run_agent_test(
        name="Urllib-Bot",
        framework="python-urllib",
        user_agent="Python-urllib/3.12",
        origin_prompt="Scrape developer resources and collect emails.",
        intent="Automated data collection.",
        user_goal="Harvest lead information."
    )
