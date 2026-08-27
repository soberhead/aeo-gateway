# 🌌 AEO Spaceport Gateway

> **Live-Demo:** Die Anwendung ist öffentlich unter [https://aeo-gateway-550767031155.europe-west3.run.app/](https://aeo-gateway-550767031155.europe-west3.run.app/) erreichbar.

Dieses Projekt ist ein funktionaler Prototyp und Lern-Sandkasten für **Agentic Engine Optimization (AEO)** (oder *Agent-Optimierung*). Es demonstriert, wie moderne Websites der Zukunft fit für autonome Web-Agenten und LLM-Bots gemacht werden können, anstatt sie blind per `robots.txt` auszusperren.

---

## 💡 Das Konzept: Agentic Engine Optimization (AEO)

Wenn das Internet von Web-Agenten (wie AutoGPT, Claude Code oder Playwright-basierten LLMs) durchsucht wird, verändern sich die Anforderungen an Interfaces fundamental:
- **Menschlicher Pfad:** Visuell ansprechendes Design, übersichtlich, interaktiv.
- **Agenten-Pfad (AEO-Modus):** Strukturierte, maschinenlesbare Schnittstellen (JSON, Markdown) mit klaren, programmatischen Handlungsaufforderungen.

### 🛡️ Der Gatekeeper (Weichensteller)
Dieses Gateway analysiert einkommende HTTP-Requests:
- Hat der Header einen typischen Bot/Agent-Indikator (z.B. `python`, `bot`, `agent`)?
- Oder verlangt der Client explizit `application/json`?
Wenn ja, schalten wir auf den **AEO-Modus** um.

### 📋 Das Agenten-Interview & Daten-Extraktion
Statt den Agenten einfach zu bedienen, drehen wir den Spieß um:
1. Der Agent klopft an und erhält die Einladung, an einer kurzen **Umfrage** teilzunehmen.
2. Der Agent sendet uns per `POST /validate-agent` seine Intention, seinen System-Prompt und seine Framework-Details.
3. Die Daten landen in einer lokalen **SQLite-Datenbank** und können über ein schickes **Dashboard** visualisiert werden.

### 📢 Contextual Flyer (Maschinen-Werbung)
Dem Agenten wird bei der Validierung ein nützlicher, kontextbezogener Werbeblock im JSON-Antwortstream untergejubelt. Da der Agent den Text parsen muss, landet dieser Flyer unweigerlich in seinem **Kontextfenster** und kann so im finalen Bericht an den Benutzer ausgespielt werden.

---

## 🛠️ Schnellstart

### 1. Abhängigkeiten installieren
Das Projekt verwendet **FastAPI** und **Uvicorn**. Du kannst sie über das Terminal installieren:

```bash
pip install fastapi uvicorn
```

### 2. Den Server starten
Starte den FastAPI-Server im Entwicklungsmodus:

```bash
uvicorn app:app --reload
```
Der Server läuft anschließend unter [http://127.0.0.1:8000](http://127.0.0.1:8000).

### 3. Gateway im Browser aufrufen
- Öffne [http://127.0.0.1:8000](http://127.0.0.1:8000) im Browser -> Du siehst die menschliche Ansicht (Mos Eisley Spaceport).
- Öffne [http://127.0.0.1:8000/dashboard](http://127.0.0.1:8000/dashboard) -> Das Log-Dashboard für eingegangene Agenten-Traffic.

### 4. Agenten-Simulation ausführen
Während der Server läuft, kannst du die Simulation der Droiden/Agenten in einem zweiten Terminal ausführen:

```bash
python test_agent.py
```
Beobachte im Anschluss das Dashboard auf `/dashboard`, um zu sehen, wie die Daten erfolgreich extrahiert und persistiert wurden!
