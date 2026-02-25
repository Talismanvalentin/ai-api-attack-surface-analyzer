# AI API Attack Surface Analyzer

A lightweight security reconnaissance tool that discovers Swagger/OpenAPI specs,
extracts API endpoints, and flags high-signal attack-surface risks.

## What this project does

This project helps security engineers and bug hunters quickly answer:
- What endpoints are exposed?
- Which endpoints look privileged or state-changing?
- Which paths likely carry object/user identifiers that may require strict authorization checks?

It is designed as an explainable, heuristic-first scanner. Findings are indicators,
not proof of vulnerability.

## Architecture

The workflow is split into small modules so each stage can be audited and extended:

- `main.py`
- CLI + interactive menu entrypoint.
- Orchestrates discovery -> parsing -> analysis.
- Renders endpoint and findings tables with `rich`.

- `core/swagger_discovery.py`
- Probes a target base URL across a curated list of common Swagger/OpenAPI paths.
- Keeps only candidates that return HTTP 200 and JSON content types.

- `core/swagger_parser.py`
- Fetches and parses Swagger/OpenAPI JSON.
- Normalizes data into `[{"method": "GET", "path": "/users/{id}"}, ...]`.

- `core/analyzer.py`
- Applies explainable heuristic rules to each endpoint.
- Produces findings with `severity` and `risks`.

- `core/reporter.py`
- Placeholder module reserved for future export/report integrations.

## Security heuristics implemented

Current analysis rules flag endpoints when they include:

- Identifier-like dynamic parameters
- Example: `/users/{userId}`, `/accounts/{account_id}`
- Rationale: common BOLA/IDOR exposure points.

- State-changing HTTP methods
- `DELETE`, `PUT`, `PATCH`
- Rationale: higher impact if authorization is weak.

- Administrative routes
- Any path containing `admin`
- Rationale: often maps to privileged operations.

All of these conditions currently map to `HIGH` severity to maximize triage visibility.

## How to run

### 1) Install dependencies

```bash
pip install requests rich
```

Optional: also record dependencies in `requirements.txt`.

### 2) Interactive mode

```bash
python main.py
```

### 3) CLI mode

```bash
python main.py discover https://api.target.com
python main.py analyze https://api.target.com/openapi.json
python main.py scan https://api.target.com
```

## Example flow

1. Discovery checks common doc paths like `/openapi.json` and `/v3/api-docs`.
2. Parser extracts endpoint paths and methods from the `paths` object.
3. Analyzer tags high-interest routes for manual testing.
4. Console output shows both raw attack surface and risk hypotheses.

## Scope and limitations

- Heuristic-based: no authentication bypass testing is performed.
- No request fuzzing, schema-aware payload generation, or active exploitation.
- JSON specs only (non-JSON docs are ignored by design).

## Suggested next extensions

- Parse request/response schemas for mass-assignment hints.
- Detect tenant boundaries and possible cross-tenant object references.
- Add confidence scoring and false-positive suppression.
- Export findings to JSON/Markdown/SARIF.
