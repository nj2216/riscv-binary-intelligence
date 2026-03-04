# riscv-binary-intelligence

Lightweight toolkit to parse, disassemble, classify, and analyze RISC‑V binaries. Intended components:
- a FastAPI backend (`app/api/routes.py`)
- core disassembly and analysis in `app/core` (ELF parsing, ISA detection, heuristics)
- model/report generation in `app/models`
- a sandbox/validator for running checks

## Quickstart (development)

1. Create and activate a virtual environment (Windows example):

```powershell
python -m venv .venv
& .venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

2. Start the API (development):

```powershell
uvicorn app.main:app --reload
```

3. Open the frontend pages in `app/static` (`index.html` / `gpt.html`) if needed.

## Project structure

- `app/main.py` — app entrypoint
- `app/api/` — API routes
- `app/core/` — disassembly, ELF parsing, heuristics, pipeline
- `app/models/` — reporting and model helpers
- `app/sandbox/` — sandbox validator
- `app/static/` — UI files

## Notes on dependencies

Current `requirements.txt`:

```
fastapi
uvicorn
pyelftools
capstone
python-multipart
```

These cover the API server and binary parsing/disassembly needs.

## Suggested upgrades and changes (high priority)

- Pin dependency versions in `requirements.txt` (e.g., `fastapi==0.100.0`) to ensure reproducible installs.
- Add a `pyproject.toml` or `poetry`/`pip-tools` workflow for reproducible environments and dependency management.
- Add type hints across `app/core` and enable `mypy` in CI to catch issues early.
- Add unit tests (pytest) for `elf_parser`, `disassembler`, and `instruction_classifier`.
- Add a `Dockerfile` for consistent deployment and a small `docker-compose.yml` for local dev if you need services.

## Suggested changes and improvements (medium priority)

- Linting and formatting: add `ruff` and `black` and a pre-commit config to enforce style.
- Add GitHub Actions workflow: run lint, mypy, and pytest on push and PRs.
- Add input validation and stricter error handling for the API endpoints in `app/api/routes.py`.
- Sanitize and limit file sizes in upload endpoints (use `python-multipart` limits).

## Performance & security

- If analyzing larger binaries, offload heavy analysis to worker processes (e.g., Celery+Redis or a simple background task queue) to avoid blocking the API.
- Run static security checks (Bandit) and scan dependencies for vulnerabilities (dependabot or `safety`).

## Documentation and DX

- Add an `OPENAPI`/Swagger overview (FastAPI provides this automatically at `/docs`). Document important endpoints and expected inputs/outputs.
- Add usage examples and sample binaries in a `tests/fixtures` folder.

## Optional automation (low effort)

- Add a `Makefile` or a set of `scripts/` commands for common tasks (`start`, `lint`, `test`, `build-image`).
- Add a CONTRIBUTING.md with development setup and testing instructions.

## Debugging and UI testing

For quick UI testing you can POST a complete report JSON to the debug endpoint which will store the report and return a temporary id you can open in the browser:

PowerShell example (file `sample_report.json` in project root):

```powershell
Invoke-RestMethod -Uri http://localhost:8000/api/debug/store_result -Method POST -ContentType 'application/json' -InFile 'sample_report.json'
```

curl example (POSIX):

```bash
curl -s -X POST http://localhost:8000/api/debug/store_result -H "Content-Type: application/json" -d @sample_report.json
```

The endpoint returns a JSON with `id` and `url`; open `/result/{id}` in your browser to view the redesigned result page with that report.

By default the server removes stored reports after the first fetch to avoid accumulating sensitive data; set the environment variable `ONE_TIME_FETCH=0` to keep reports until server restart.

## Next steps I can take

- Pin dependency versions and convert `requirements.txt` into `requirements-dev.txt` + pinned `requirements.txt`.
- Add a basic GitHub Actions workflow for linting and tests.
- Add `pyproject.toml` using Poetry or `pip-tools` for reproducible installs.

If you want, I can: pin dependencies and add CI config, scaffold tests for the core modules, or create a `Dockerfile` — which should I do first?
