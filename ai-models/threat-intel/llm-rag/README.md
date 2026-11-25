# LLM + RAG — grounded threat-intelligence reports

The reporting half of the AEGEX AI stack, packaged so it runs **on its own**.

It takes detections and writes a report that explains each one against MITRE
ATT&CK and CISA KEV, with a citation on every claim. It never loads the
autoencoder, E-GraphSAGE or the type classifier, and it imports neither
TensorFlow nor PyTorch.

```
detections.json  ──▶  build_question()  ──▶  retrieve 5 of 3,312 docs
                                                      │
                      report.md + report.json  ◀───  local LLM writes,
                                                      cites, or abstains
```

---

## Why it is split this way

The two halves of the AI stack meet at **a file**, not at a function call:

| Half | Owns | Produces / consumes |
|---|---|---|
| Detection | autoencoder, E-GraphSAGE, type classifier | writes `detections.json` |
| **Reporting (this one)** | knowledge base, retriever, LLM | reads `detections.json` |

Because the interface is a JSON file, whoever owns this half can build and
test everything here while the detection half is still unwritten — run it
against `examples/detections.json` and it works. Nothing in this folder
depends on a trained model file.

The same code also runs inside the combined pipeline; splitting it out
changes the packaging, not the behaviour.

---

## The contract

`examples/detections.json` is the specification. Required on every detection:

| Field | Example |
|---|---|
| `id` | `"alert-001"` |
| `attack_type` | `"Port_Scanning"` |
| `source` | `"192.168.1.47"` |
| `target` | `"192.168.1.50"` |

Optional: `detected_at`, and an `evidence` object. Evidence is free-form and
is copied into the report untouched, so the detection half can add fields
without this half changing. A detection carrying **no evidence at all** still
produces a valid report — that is what makes this half testable alone.

Output is written twice: `report.md` to read, `report.json` for the backend.

---

## Install

This half needs the RAG engine, which is a separate MIT-licensed project:

```bash
git clone https://github.com/rvong65/threat-intelligence-assistant
pip install -r threat-intelligence-assistant/requirements.txt
```

Then Ollama with two models:

```bash
ollama pull nomic-embed-text
ollama pull gemma3:4b
```

Copy `.env.example` into the `threat-intelligence-assistant` folder as `.env`.

Point this package at that folder:

```powershell
$env:RAG_DIR = "C:\path\to\threat-intelligence-assistant"
```

---

## Run

Check the questions first — this calls no model and takes a second:

```bash
python report.py --detections examples/detections.json --dry-run
```

Then generate the reports:

```bash
python report.py --detections examples/detections.json
```

Ask the knowledge base a single question:

```bash
python ask.py "How is T1059 used by threat actors?"
python ask.py "What is the capital of Egypt?"      # should abstain
```

---

## The knowledge base

| Source | Documents |
|---|---|
| MITRE ATT&CK — techniques | 697 |
| CISA KEV — exploited vulnerabilities | 1,614 |
| MITRE — software and malware | 821 |
| MITRE — threat groups | 174 |
| **Total chunks** | **3,312** |

Everything runs on the machine through Ollama. No external API, no key, and
no honeypot data leaves the host.

### Three guards against hallucination

- every sentence must carry a citation such as `[T1059]`
- inventing an ID that is not in the retrieved documents is forbidden
- below the confidence threshold the system **abstains** instead of answering

An abstention is the system working, not failing. `alert-004` in the sample
file is there to exercise that path.

---

## Two things that will bite you

**The embedding model is not interchangeable.** The prebuilt FAISS index was
embedded with `nomic-embed-text`. Another model produces the same 768
dimensions, so nothing raises an error — retrieval just quietly returns the
wrong documents. Keep `EMBEDDING_MODEL=nomic-embed-text` unless you rebuild
the index.

**A bare class name is rejected.** The RAG layer refuses anything that does
not read as a threat-intelligence question, so sending `"Port_Scanning"` gets
nothing back. `build_question()` always produces a full sentence carrying the
words *MITRE ATT&CK*; all 15 Edge-IIoTset classes were checked against the
real filter and all pass.

---

## Closing the IoT gap

Counting the shipped corpus: **`IoT` appears in 12 documents and `MQTT` in
one.** It is strong on general network attacks and thin on IoT, which is this
project's subject.

`knowledge/` adds the **OWASP IoT Top 10** to fix that:

```bash
python knowledge/add_owasp_iot.py --dry-run
python knowledge/add_owasp_iot.py
```

The 2018 release is still current — checked against two sources on
2026-11-15, with no later revision published.

### It is not just a data load

The RAG project accepts five source types and recognises four shapes of
citation ID. Dropping new documents in without touching those two places
gives the worst possible outcome: the documents **are** retrieved, the model
**does** cite them, the citation checker does not recognise the IDs, and
confidence silently drops — the same failure mode as an answer with no
citations at all.

Measured on the real code:

| `[IOT-I1]` in an answer | extracted as |
|---|---|
| before the patch | `[]` — invisible |
| after the patch | `['IOT-I1']` |

So the script patches both places first, backing each file up, before it
embeds anything. It is idempotent, and it stops with instructions rather than
guessing if upstream has changed those lines.

### Each item carries its detection classes

Every document ends with the Edge-IIoTset classes that item covers, and that
line is embedded with the text on purpose — it is what pulls `IOT-I1` up when
the question names a detected `Password` attack rather than an OWASP term.
All 14 attack classes map to at least one item.

### NVD enrichment

The NVD loader ships with the project and is already wired into the ingest
script, but it sends no API key while sleeping 0.6 s between requests. NVD
allows **5 requests per 30 seconds** without a key — one every six seconds —
so at that pace almost every call returns 403 or 429. They are caught, logged
as warnings, and the loop continues, so a throttled run looks like a
successful one and brings back a handful of CVEs instead of hundreds.

0.6 s is the right pace *with* a key (50 per 30 s), which is what the loader
was written for. `knowledge/enable_nvd.py` adds the missing key, makes the
pace a setting, and counts failures loudly instead of only logging them:

```bash
python knowledge/enable_nvd.py --dry-run
python knowledge/enable_nvd.py
```

Then get a free key (email only) at
<https://nvd.nist.gov/developers/request-an-api-key>, put `NVD_API_KEY=...`
and `NVD_SLEEP_SECONDS=0.6` in the project's `.env`, and run:

```bash
python scripts/ingest.py --validate-only --enrich-nvd --nvd-limit 10
python scripts/ingest.py --build-index --enrich-nvd --nvd-limit 100
```

Results are cached in `data/processed/nvd_cache.json`, so each run resumes
where the last one stopped. Without a key, leave the pace at 6 s: 100 CVEs
then takes ten minutes.

Note what this covers: it enriches the **CVEs already in CISA KEV**, not the
whole of NVD. Worth saying plainly rather than claiming full NVD coverage.

### IoT CVEs beyond KEV

KEV is the exploited-in-the-wild set, but small and not IoT-specific. The full
NVD is 300,000+ CVEs — mostly noise for an IoT honeypot and ten-plus hours to
embed locally. `knowledge/add_iot_cve.py` takes the useful middle: CVEs whose
descriptions mention IoT technology (MQTT, CoAP, Modbus, router firmware, IP
camera, SCADA, …), pulled by NVD keyword search with pagination — a handful of
requests, not one per CVE. CVEs already in the index from KEV are skipped.

```bash
python knowledge/add_iot_cve.py --dry-run       # the keyword plan
python knowledge/add_iot_cve.py --fetch         # download to a local cache
python knowledge/add_iot_cve.py --build-index   # embed the cache in
```

Run `enable_nvd.py` and add the NVD key first — the key is read from the
project's `.env`. No source edits: the project already has an `nvd_cve` source
type and already recognises `CVE-…` citations, so this only adds documents.

### Still missing

CWE and CAPEC. Both need the same treatment as OWASP: a source type, a
citation pattern, and documents — not documents alone.
