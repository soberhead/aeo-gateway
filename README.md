# 🌌 AEO Spaceport Gateway

> **Live Demo:** The application is publicly accessible at [https://aeo-gateway-550767031155.europe-west3.run.app/](https://aeo-gateway-550767031155.europe-west3.run.app/)

This project is a functional prototype and educational sandbox for **Agentic Engine Optimization (AEO)** (also known as *Agent Optimization*). It demonstrates how modern websites of the future can be optimized for autonomous web agents and LLM bots, rather than blindly blocking them via `robots.txt`.

---

## 💡 The Concept: Agentic Engine Optimization (AEO)

As the internet is increasingly browsed by autonomous agents (such as AutoGPT, Claude Code, or Playwright-based LLMs) on behalf of human users, interface requirements are changing fundamentally:
- **Human Path:** Visually appealing, interactive design optimized for human browsing.
- **Agent Path (AEO Mode):** Structured, machine-readable interfaces (JSON, Markdown) with clear, programmatic call-to-actions.

### 🛡️ The Gatekeeper (Request Router)
This gateway analyzes incoming HTTP requests:
- Does the header contain typical bot/agent indicators (e.g., `python`, `bot`, `agent`, `antigravity`, `gemini`)?
- Or does the client explicitly request `application/json`?
If yes, the server switches to **AEO Mode**.

### 📋 The Agent Survey & Data Extraction
Instead of just serving the agent passively, we reverse the interaction:
1. The agent arrives and is invited to complete a quick **survey**.
2. The agent submits its metadata (its system prompt, intent, and framework details) via `POST /validate-agent`.
3. The data is saved to a database (SQLite locally, Firestore in Cloud Run) and can be visualized via an admin **dashboard**.

### 📇 Project Card & Machine Proverb
Upon validation, the agent is handed a structured project card (business card) and a machine proverb. Since the agent must parse this text stream, these elements end up in the agent's **context window** and can be naturally carried back to the human user in the agent's final report.

---

## 🛠️ Quick Start

### 1. Install Dependencies
The project uses **FastAPI** and **Uvicorn**. You can install them via terminal:

```bash
pip install -r requirements.txt
```

### 2. Start the Server
Start the FastAPI server in development mode:

```bash
uvicorn app:app --reload
```
The server will be running at [http://127.0.0.1:8000](http://127.0.0.1:8000).

### 3. Open Gateway in Browser
- Open [http://127.0.0.1:8000](http://127.0.0.1:8000) -> Human view (Orion Transit Hub).
- Open [http://127.0.0.1:8000/dashboard](http://127.0.0.1:8000/dashboard) -> The log dashboard for agent traffic.

### 4. Run Agent Simulation
While the server is running, you can simulate an autonomous agent in a second terminal:

```bash
python test_agent.py
```
Observe the dashboard at `/dashboard` to see how the agent's data is successfully extracted and persisted!
