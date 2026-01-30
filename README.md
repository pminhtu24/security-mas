# Security Scanner MAS

A **Multi-Agent System (MAS)** for security scanning that combines **SAST** (Static Application Security Testing) and **SCA** (Software Composition Analysis) with parallel execution and AI-powered aggregation. Built with [LangGraph](https://github.com/langchain-ai/langgraph) for workflow orchestration.

## Features

- **Coordinator** – Discovers project files to scan (Python, JS/TS, Java, PHP, Go, Ruby, etc.)
- **SAST worker** – Runs [Semgrep](https://semgrep.dev/) for code vulnerability detection
- **SCA worker** – Runs [Snyk](https://snyk.io/) for dependency vulnerability scanning
- **Parallel execution** – SAST and SCA run concurrently after the coordinator
- **Aggregator** – Uses an LLM to unify findings, assign risk levels, and produce actionable fixes (including unified-diff patches where applicable)
- **Structured report** – JSON output with summary, per-issue details, and remediation priority

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
                    │   AGGREGATOR     │
                    │ (LLM analysis)  │
                    └────────┬────────┘
                             ▼
                         [Report]
```

## Prerequisites

- **Python 3.10+**
- **Semgrep** – [Install](https://semgrep.dev/docs/getting-started/installation/) and ensure `semgrep` is on your `PATH`
- **Snyk** – [Install](https://docs.snyk.io/snyk-cli/install-the-snyk-cli) and [authenticate](https://docs.snyk.io/snyk-cli/authenticate-the-cli-with-your-account) (`snyk test` must work)
- **OpenAI API key** – Used by the aggregator LLM. Set `OPENAI_API_KEY` in your environment or in a `.env` file.

## Installation

1. Clone the repository and enter the project directory:

   ```bash
   cd security-mas
   ```

2. Create a virtual environment and install dependencies:

   ```bash
   python -m venv .venv
   source .venv/bin/activate   # Linux/macOS
   # or:  .venv\Scripts\activate   # Windows
   ```

3. Install from the lock file (if you use [uv](https://github.com/astral-sh/uv)):

   ```bash
   uv pip sync requirements.lock
   ```

   Or install core dependencies manually:

   ```bash
   pip install langchain langgraph langchain-openai pydantic python-dotenv semgrep
   ```

4. Create a `.env` file in the project root (optional but recommended):

   ```env
   OPENAI_API_KEY=sk-your-openai-api-key
   ```

## Usage

Scan a project directory and write the report to the default path `results/report.json`:

```bash
python main.py --project /path/to/your/project
```

Specify a custom report path:

```bash
python main.py --project /path/to/your/project --output results/my_report.json
```

Example with the included test project:

```bash
python main.py --project test_project --output results/report.json
```

After the run, the console prints a summary (total files, SAST/SCA issue counts, total vulnerabilities), and the full report is saved as JSON.

## Report format

The output JSON contains:

| Field                  | Description                                                                                                        |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `summary`              | `total_files_scanned`, `sast_issues`, `sca_issues`, `total_issues`, `overall_risk`                                 |
| `issues`               | List of unified security issues: `tool`, `risk_level`, `message`, `location`, `fix` (description + optional patch) |
| `remediation_priority` | Ordered list of 3–5 concrete remediation steps                                                                     |

## Project structure

```
security-mas/
├── main.py                 # CLI entrypoint
├── mas_core/
│   ├── graph.py            # LangGraph workflow (nodes + edges)
│   ├── nodes.py            # Coordinator, SAST worker, SCA worker, Aggregator
│   ├── state.py            # ScanState TypedDict
│   └── schemas/
│       ├── security.py     # Pydantic models (SecurityIssue, LLMAnalysisResult, etc.)
│       └── llm_analyzer.py # LLM invocation and SAST/SCA formatting
├── tools/
│   ├── sast_tool.py        # Semgrep wrapper
│   └── sca_tool.py         # Snyk wrapper (pip/requirements.txt)
├── test_project/           # Sample project with intentional vulnerabilities
├── results/                # Default directory for report.json
├── requirements.lock
└── README.md
```

## Test project

The `test_project/` directory contains sample files with intentional issues (e.g. SQL injection, XSS, insecure pickle, path traversal, hardcoded secrets) and a `requirements.txt` with outdated dependencies. Use it to verify the scanner and report format:

```bash
python main.py --project test_project
```

## Supported languages (SAST)

File discovery includes: `.py`, `.js`, `.jsx`, `.ts`, `.tsx`, `.java`, `.php`, `.go`, `.rb`. Directories such as `node_modules`, `.git`, `venv`, `__pycache__`, `build`, `dist` are skipped.

## SCA (dependencies)

Snyk is run for **Python** projects: the tool looks for `requirements.txt` in the project root or under subdirectories and runs `snyk test` with `--package-manager=pip`. Other ecosystems can be added by extending `tools/sca_tool.py`.

## License

See the repository for license information.
