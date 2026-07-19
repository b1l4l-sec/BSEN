# Contributing to BSEN

Thanks for considering a contribution.

## Ground rules

- **Read-only, always.** Any PR that writes to system state, modifies
  configuration, kills processes, or performs any form of exploitation
  will be rejected outright, regardless of intent.
- New scanners go through the plugin system (see
  `docs/PLUGIN_DEVELOPMENT.md`) — don't add scanning logic to `cli.py`
  or `core/`.
- Every new `Finding`-producing check should include a clear
  `recommendation` and, where applicable, a MITRE ATT&CK `mitre_technique`.

## Code style

- Format with `black` and `isort`.
- Lint with `flake8`.
- Type-check with `mypy` where practical (the codebase uses type hints
  throughout `core/` and `risk_engine/`).

```bash
pip install black isort flake8 mypy
black bsen/
isort bsen/
flake8 bsen/
mypy bsen/
```

## Tests

Add tests under `tests/` for any new module. Run with:

```bash
pip install pytest
pytest tests/ -v
```

## Pull requests

1. Fork, branch off `main`.
2. Keep PRs focused — one plugin or one fix per PR is easiest to review.
3. Update `README.md`'s module table if you add a new scanner category.
4. Describe what platform(s) you tested on.
