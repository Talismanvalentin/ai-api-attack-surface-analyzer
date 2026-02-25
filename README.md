# API Attack Surface Analyzer

Static API reconnaissance tool for OpenAPI/Swagger specifications.

It discovers API specification endpoints, extracts method/path metadata, applies deterministic risk heuristics, and can optionally call an LLM (via OpenRouter) for structured hypothesis generation and systemic risk review.

This project is designed for triage and review acceleration, not automated exploitation.

## Scope

This repository currently targets:

- Discovery of exposed Swagger/OpenAPI JSON documents.
- Extraction of endpoints (`method`, `path`) from specification `paths`.
- Heuristic identification of high-interest routes (for example: object identifiers and state-changing operations).
- Optional LLM-assisted analysis that outputs structured security hypotheses.

Out of scope:

- Source-code analysis.
- Runtime exploit validation.
- Authentication bypass testing.
- Fuzzing or payload generation.

## Architecture

Pipeline:

1. Discovery
2. Parsing
3. Heuristics
4. Optional LLM reasoning
5. Reporting

Module layout:

- `main.py`: CLI entrypoint and workflow orchestration.
- `core/swagger_discovery.py`: probes common OpenAPI/Swagger documentation paths.
- `core/swagger_parser.py`: fetches/parses JSON specs and normalizes endpoint metadata.
- `core/analyzer.py`: rule-based endpoint risk signal detection.
- `core/reporter.py`: reporting/output layer boundary.

### Flow Details

1. Discovery checks a curated list such as `/openapi.json`, `/swagger.json`, `/v3/api-docs`.
2. Parser loads JSON and extracts endpoint objects from `paths`.
3. Heuristic analyzer tags routes with deterministic rules (for example: identifier-bearing paths, privileged-looking paths, state-changing methods).
4. If enabled, an LLM receives bounded structured endpoint context and returns:
   - Endpoint-level vulnerability hypotheses.
   - Global/systemic risk observations.
5. Reporter prints structured findings for manual review.

## Threat Model

The analyzer assumes a realistic SaaS/API security review context:

- Attacker has network access to published API routes.
- Attacker can authenticate as a low-privilege user (typical B2B/B2C threat model).
- Risk is concentrated in authorization and business-logic gaps, especially:
  - BOLA/IDOR on object-referencing endpoints.
  - Privilege boundary mistakes on admin or state-changing operations.
  - Unsafe update patterns (for example mass-assignment style behavior inferred from endpoint semantics).

This is a structural risk triage model based on API contract metadata, not proof of vulnerability.

## LLM Integration (Constrained and Structured)

LLM usage is optional and intentionally bounded:

- Input is structured endpoint metadata (not source code, not internal secrets).
- Prompts require JSON-structured output with explicit fields.
- LLM output is treated as hypothesis generation, not ground truth.
- Deterministic heuristics remain the primary baseline.
- Final interpretation is human-led and should be validated through manual security testing.

## Usage

Install dependencies:

```bash
pip install -r requirements.txt
```

Discovery only:

```bash
python main.py discover https://api.target.com
```

Analyze known OpenAPI/Swagger URL:

```bash
python main.py analyze https://api.target.com/openapi.json
```

Full scan (discover + analyze):

```bash
python main.py scan https://api.target.com
```

Interactive mode:

```bash
python main.py
```

## Example Output

```text
Extracted Endpoints
+--------+-----------------------+
| Method | Path                  |
+--------+-----------------------+
| GET    | /users/{userId}       |
| PATCH  | /users/{userId}       |
| DELETE | /admin/accounts/{id}  |
+--------+-----------------------+

Potential Attack Vectors
+----------+--------+----------------------+---------------------------------------------+
| Severity | Method | Path                 | Risk                                        |
+----------+--------+----------------------+---------------------------------------------+
| HIGH     | PATCH  | /users/{userId}      | Sensitive identifier in path: userId        |
| HIGH     | PATCH  | /users/{userId}      | State-changing method (authorization check) |
| HIGH     | DELETE | /admin/accounts/{id} | Administrative endpoint detected            |
+----------+--------+----------------------+---------------------------------------------+
```

## Limitations

- Heuristic and metadata-driven: can produce false positives and false negatives.
- JSON OpenAPI/Swagger documents are primary input; non-JSON docs may be skipped.
- No runtime behavior validation (authorization checks, tenant boundaries, token handling, or rate-limit enforcement are not directly verified).
- LLM analysis quality depends on model behavior and prompt compliance.
- Findings are prioritization signals intended to guide manual testing.

## Engineering Notes

- Deterministic rules are explainable and auditable.
- Module boundaries are explicit to keep discovery/parsing/analysis separable.
- This project is appropriate as a backend/AppSec portfolio artifact when paired with tests and reproducible sample inputs.
