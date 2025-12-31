# Repository Guidelines

## Project Structure & Module Organization
- `src/` holds the core library and CLI: `stegano_core.py` (encoding), `aas_injector.py` (watermark injection), `aas_tracer.py` (forensic tracing), `cli.py` (commands), and `__init__.py` (public API).
- `tests/` contains pytest suites (currently `test_aas_stegano_trace.py`).
- `examples/` provides sample AAS JSON files for manual runs and demos.
- `docs/` includes deeper technical notes, such as `docs/TECHNICAL_DETAILS.md`.

## Build, Test, and Development Commands
- Run the CLI locally:
  ```bash
  python -m src.cli --help
  python -m src.cli inject examples/industrial_motor.json "Recipient-Id"
  python -m src.cli trace examples/industrial_motor.json
  ```
- Run tests:
  ```bash
  python -m pytest tests/ -v
  ```
- Install dev tooling (pytest, black, ruff, mypy):
  ```bash
  pip install -e ".[dev]"
  ```

## Coding Style & Naming Conventions
- Python 3.8+ with 4-space indentation.
- Format with Black (line length 100) and lint with Ruff (line length 100).
- Mypy is configured with `disallow_untyped_defs = true`; add type hints to new functions/classes.
- Naming follows standard Python conventions: `snake_case` for functions/variables and `PascalCase` for classes.

## Testing Guidelines
- Framework: pytest.
- Test discovery uses `tests/`, `test_*.py`, and `test_*` functions.
- No explicit coverage threshold is defined; focus on unit tests for encoding/decoding and integration tests for inject/trace workflows.

## Commit & Pull Request Guidelines
- This checkout does not include Git history, so no commit message convention can be inferred.
- Until a convention is documented, use short, imperative subjects (e.g., "Add tracer edge case tests").
- PRs should include: a concise summary, the test command you ran, and sample inputs/outputs if behavior changes (especially in watermark injection or tracing).

## Data Integrity & Configuration Tips
- Preserve zero-width watermark characters when writing JSON: use `ensure_ascii=False` and UTF-8 output.
- Avoid tooling that normalizes or strips zero-width Unicode characters, or you may destroy forensic evidence.
