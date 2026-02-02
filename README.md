# Security Scanner MAS

A **Multi‑Agent System (MAS)** for application security scanning that combines:

- **SAST** (Static Application Security Testing) via **Semgrep**
- **SCA** (Software Composition Analysis) via **Snyk**
- **LLM aggregation** to unify findings and generate actionable fixes (including unified-diff patches when possible)

Workflow orchestration is implemented with [LangGraph](https://github.com/langchain-ai/langgraph).

## What it does

- **Coordinator**: discovers source files to scan (multi-language)
- **SAST worker**: runs Semgrep over discovered files
- **SCA worker**: runs Snyk over Python dependencies (`requirements.txt`)
- **Aggregator**: calls an LLM to deduplicate findings, assign risk levels, and produce fixes
- **Output**: a single JSON report (default `results/report.json`)

## Architecture

```
                    ┌─────────────────┐
                    │   COORDINATOR   │
                    │ (discover files)│
                    └────────┬────────┘
                             │
              ┌──────────────┴──────────────┐
              ▼                             ▼
     ┌─────────────────┐           ┌─────────────────┐
     │  SAST WORKER     │           │  SCA WORKER     │
     │  (Semgrep)       │           │  (Snyk)         │
     └────────┬────────┘           └────────┬────────┘
              │                             │
              └──────────────┬──────────────┘
                             ▼
                    ┌─────────────────┐
                    │   AGGREGATOR    │
                    │ (LLM analysis)  │
                    └────────┬────────┘
                             ▼
                         [Report]
```

## Requirements

- **Python 3.11+** (see `pyproject.toml`)
- **Semgrep CLI** available on `PATH` (`semgrep --version`)
- **Snyk CLI** available on `PATH` and authenticated (`snyk auth`, then `snyk test` works)
- **OpenAI API key** for the aggregator: set `OPENAI_API_KEY` (env var or `.env` file)

## Installation

This repo includes `uv.lock`, so the simplest setup is with [uv](https://github.com/astral-sh/uv).

### Option A: Install with uv (recommended)

```bash
uv sync --group dev
```

### Option B: Install with pip

```bash
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .
pip install -r test_project/requirements.txt  # optional, only if you want a local scan target
```

### Environment variables

Create a `.env` file in the repo root (optional):

```env
OPENAI_API_KEY=your_key_here
```

## Usage (CLI)

Scan a project directory and write the report to the default path `results/report.json`:

```bash
python main.py --project /path/to/your/project
```

Write to a custom output path:

```bash
python main.py --project /path/to/your/project --output results/my_report.json
```

Run against the included intentionally-vulnerable sample project:

```bash
python main.py --project test_project --output results/report.json
```

## Usage (API)

Start the FastAPI server:

```bash
uvicorn api_server.api_server:app --host 0.0.0.0 --port 8000 --reload
```

Endpoints:

- `GET /health`: health status
- `POST /scan`: upload a ZIP codebase and start a background scan
- `GET /scan/{scan_id}`: poll status and fetch results

Example scan request (ZIP upload):

```bash
curl -X POST "http://localhost:8000/scan?project_name=my-project" \
  -F "codebase=@/path/to/project.zip"
```

Poll for results:

```bash
curl "http://localhost:8000/scan/<scan_id>"
```

## Report format

The output JSON contains:

| Field                  | Description                                                                                                                 |
| ---------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `summary`              | `total_files_scanned`, `sast_issues`, `sca_issues`, `total_issues`, `overall_risk`                                          |
| `issues`               | Unified issues with `tool`, `risk_level`, `message`, optional `location`, and optional `fix` (description + optional patch) |
| `remediation_priority` | Ordered list of 3–5 concrete remediation steps                                                                              |

## Scanning behavior

### SAST (Semgrep)

- **File discovery**: `.py`, `.js`, `.jsx`, `.ts`, `.tsx`, `.java`, `.php`, `.go`, `.rb`
- **Ignored dirs**: `node_modules`, `.git`, `venv`, `.venv`, `__pycache__`, `build`, `dist`
- **Execution**: Semgrep runs with `--config auto` and returns JSON results

### SCA (Snyk)

- **Python only (current implementation)**: searches for `requirements.txt` under the target project
- **Execution**: runs `snyk test --json --package-manager=pip --file=<requirements.txt>`

## Project structure

```
security-mas/
├── main.py                    # CLI entrypoint
├── api_server/
│   └── api_server.py          # FastAPI service (zip upload + background scan)
├── mas_core/
│   ├── graph.py               # LangGraph workflow
│   ├── nodes.py               # Coordinator, SAST worker, SCA worker, Aggregator
│   ├── state.py               # Scan state definition
│   └── schemas/
│       ├── security.py        # Pydantic models (SecurityIssue, LLMAnalysisResult, ...)
│       └── llm_analyzer.py    # LLM prompt + findings formatting
├── tools/
│   ├── sast_tool.py           # Semgrep wrapper
│   └── sca_tool.py            # Snyk wrapper
├── test_project/              # Sample project with intentional vulnerabilities
├── results/                   # Default output directory
└── uv.lock
```

## Notes / limitations

- The aggregator currently samples up to **15 SAST** and **15 SCA** findings for LLM analysis (see `mas_core/schemas/llm_analyzer.py`).
- Semgrep/Snyk timeouts are currently **60s** each (see `tools/sast_tool.py` and `tools/sca_tool.py`).
