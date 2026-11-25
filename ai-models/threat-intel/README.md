# AEGEX - Threat Intelligence (LLM + RAG)

Task E. Takes the detections from the AI models (`detections.json`) and writes a
grounded threat-intelligence report: every claim is cited, the system abstains when
the evidence is weak, and each attack gets **Blue Team recommendations**.
Runs fully on your laptop with Ollama. No cloud, no API key.

```
ai-models/threat-intel/
  llm-rag/                        report.py, ask.py, examples/detections.json, knowledge/
  threat-intelligence-assistant/  RAG engine + Streamlit UI + PREBUILT FAISS index (8,338 chunks)
```

The knowledge base (ATT&CK, CISA KEV, IoT CVEs, OWASP IoT Top 10, CWE, CAPEC,
ATT&CK mitigations) is already built and committed. Do **not** rebuild it.

## 1. Get the code

```powershell
git clone https://github.com/Youssef-Tarek-2005/Graduation-Project-Aegex.git
cd Graduation-Project-Aegex
git pull                                  # later, to get updates
```

## 2. Install Ollama and the two models (required)

Install Ollama from https://ollama.com, then:

```powershell
ollama pull nomic-embed-text   # embedding model - MUST be this one (the index was built with it)
ollama pull gemma3:4b          # the local LLM that writes the report
ollama list                    # both should be listed
```

## 3. Python environment and config

```powershell
cd ai-models\threat-intel\threat-intelligence-assistant
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
```

## 4. Run

Ask one question (quick check that the RAG works):

```powershell
cd ..\llm-rag
python ask.py "How is a password brute-force attack mitigated on an IoT device?"
python ask.py "What is the capital of Egypt?"      # should abstain
```

Generate the report from detections:

```powershell
python report.py --detections examples\detections.json
#   -> report.md    (read this)
#   -> report.json  (for the backend / dashboard)
```

Each detection runs two queries (assessment + Blue Team), so 5 detections take a
few minutes. Add `--no-recommendations` to go faster.

The chat UI (optional):

```powershell
cd ..\threat-intelligence-assistant
streamlit run app.py
```

## Connecting the detection models

Everything meets at `detections.json`. Required on every detection: `id`,
`attack_type`, `source`, `target`. Optional: `detected_at` and a free-form
`evidence` object (copied into the report as-is). See `llm-rag/examples/detections.json`.

```powershell
python report.py --detections path\to\your\detections.json
```

`attack_type` is the label your model outputs (e.g. `Password`, `DDoS_ICMP`,
`Port_Scanning`). Labels from Edge-IIoTset, TON_IoT, Bot-IoT, CICIoT2023 and N-BaIoT
are mapped in `llm-rag/knowledge/attack_families.json`. If your model uses a label that
is not there, add it to the right family's `labels` list.

## Troubleshooting

| Problem | Fix |
|---|---|
| `the RAG project is not at ...` | Run from `llm-rag`, or set `$env:RAG_DIR` to the full path of `threat-intelligence-assistant` |
| Cannot connect to Ollama | Make sure Ollama is running; keep `OLLAMA_BASE_URL=http://127.0.0.1:11434` in `.env` |
| Answers look unrelated | Embedding model changed. It must stay `nomic-embed-text` |
| Very slow first answer | Normal: the model is loading. Later calls are faster |
