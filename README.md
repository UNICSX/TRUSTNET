# TRUSTNET — Multi-Agent Cybersecurity Investigation Framework

TRUSTNET is an autonomous, multi-agent system that investigates suspicious
emails, hunts for threats, and triages SOC alerts. A **Coordinator** agent
plans an investigation, delegates work to specialist agents, aggregates their
findings, and produces a single executive report. A Streamlit dashboard
visualises the whole investigation live.

> **Note:** This is an academic / demonstration project. The specialist tools
> (domain age, IP reputation, MITRE mapping, SIEM lookups, etc.) are **mocked
> heuristics** for demonstration and are not connected to live threat-intel
> feeds. It is a *defensive* security tool — it detects and analyses phishing
> and threats; it does not create them.

---

## Architecture

```
                    ┌────────────────────┐
                    │   Coordinator      │  plans, delegates, aggregates,
                    │   Agent            │  writes the executive report
                    └─────────┬──────────┘
          ┌───────────────────┼───────────────────┐
          ▼                   ▼                   ▼
  ┌───────────────┐  ┌────────────────┐  ┌──────────────────┐
  │  Phishing     │  │  Threat        │  │  SOC Alert       │
  │  Investigation│  │  Hunting       │  │  Triage          │
  │  Agent        │  │  Agent         │  │  Agent           │
  └───────────────┘  └────────────────┘  └──────────────────┘
```

Every specialist replies using a shared **Agent Communication Protocol (ACP)**
so the Coordinator can parse, merge, and reason over their outputs
consistently.

## Specialist agents

- **Phishing Investigation Agent** — analyses sender/reply-to mismatch, domain
  spoofing, typosquatting, suspicious URLs, and social-engineering language.
- **Threat Hunting Agent** — investigates IOCs: processes, network
  connections, IP reputation, startup persistence, and MITRE ATT&CK mapping.
- **SOC Alert Triage Agent** — investigates alerts: parent processes, hash
  reputation, user activity, asset criticality, and prior alerts.

## Tech stack

- **Python**
- **Groq** LLM API (`llama-3.1-8b-instant`) for every agent
- **Streamlit** for the live dashboard

---

## Project structure

```
phishing-agent/
├── main.py                 # CLI entry point (runs an investigation in the terminal)
├── config.py               # Models, limits, env var names
├── coordinator.py          # Coordinator orchestration
├── agent_core.py           # BaseAgent (shared agent loop)
├── acp.py / acp_prompts.py # Agent Communication Protocol
├── coordinator_prompts.py
├── phishing_agent.py / phishing_prompts.py / phishing_tool_specs.py
├── tools.py                # Phishing analysis tools
├── tool_registry.py        # Generic tool registry
├── soc/                    # SOC specialist (agent, prompts, tools, specs)
├── threat_hunter/          # Threat specialist (agent, prompts, tools, specs)
├── data/                   # Sample emails
└── Dashboard/
    ├── app.py              # Streamlit entry point
    ├── assets/style.css
    ├── Components/         # Dashboard UI components
    └── utils/api.py        # Bridges the dashboard to the coordinator
```

---

## Getting started (local)

### 1. Clone

```bash
git clone https://github.com/<your-username>/phishing-agent.git
cd phishing-agent
```

### 2. Create a virtual environment

```bash
python -m venv venv
# Windows (PowerShell)
.\venv\Scripts\Activate.ps1
# macOS / Linux
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Add your API keys

Copy the example file and fill in your Groq key(s):

```bash
cp .env.example .env      # Windows: copy .env.example .env
```

Get a free Groq API key at <https://console.groq.com/keys>. You can reuse the
same key for all four values, or use separate keys.

```
GROQ_COORDINATOR_KEY=your_groq_key_here
GROQ_PHISHING_KEY=your_groq_key_here
GROQ_THREAT_KEY=your_groq_key_here
GROQ_SOC_KEY=your_groq_key_here
```

---

## Running

### Dashboard (recommended)

```bash
streamlit run Dashboard/app.py
```

Then open the URL Streamlit prints (usually <http://localhost:8501>).

### Command line

```bash
python main.py
```

Enter an investigation request when prompted. The final report is printed and
saved to `final_report.json`.

### Example investigation input

```
Received an email from support@micros0ft-security.com asking users to verify
their Office365 credentials immediately. The email contains the link
https://micros0ft-login-security.xyz — please investigate whether this is a
phishing campaign.
```

---

## Deploying to Streamlit Community Cloud

1. Push this repo to GitHub (see below).
2. Go to <https://share.streamlit.io> and sign in with GitHub.
3. Click **New app**, choose this repo, and set the main file to
   `Dashboard/app.py`.
4. Under **Advanced settings**, pick a supported Python version (e.g. 3.12).
5. In the **Secrets** field, paste your keys in TOML format (top-level keys
   become environment variables, so your existing `os.getenv(...)` code works):

   ```toml
   GROQ_COORDINATOR_KEY = "your_groq_key_here"
   GROQ_PHISHING_KEY = "your_groq_key_here"
   GROQ_THREAT_KEY = "your_groq_key_here"
   GROQ_SOC_KEY = "your_groq_key_here"
   ```

6. Click **Deploy**. Share the resulting URL — no setup required on the
   viewer's side.

---

## Security

- Never commit your `.env` file or real API keys. `.gitignore` already excludes
  them.
- If a key is ever pushed by accident, rotate it immediately in the Groq
  console.
