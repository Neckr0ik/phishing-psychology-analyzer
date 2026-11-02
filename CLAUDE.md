# CLAUDE.md — phishing-psychology-analyzer

Portfolio project (Neckr0ik / Giovanni Oliveira, "Hybrid Intelligence" portfolio). Scores the **wording** of a message (email/SMS) on 8 social-engineering levers (urgency, authority, fear, scarcity, reciprocity, social proof, false familiarity, curiosity), maps each to a cognitive bias and the closest MITRE ATT&CK technique (context only, not an official mapping), and produces a 0–100 persuasion-pressure score with red flags. It is **not** a phishing classifier (no labelled-corpus evaluation; legitimate marketing scores HIGH by design).

## Stack

Python 3.11+, vaderSentiment, matplotlib, numpy, pytest (`requirements.txt`). English only. No API keys, no network.

## Structure

```
main.py           # CLI: batch of samples, --text / --file (mutually exclusive), --json, --no-charts
src/taxonomy.py   # 8 vectors: keywords, biases, ATT&CK context, weights, risk bands
src/analyzer.py   # NFKC normalisation, invisible-char stripping, whole-word matching, scores, red flags
src/reporter.py   # radar/comparison/heatmap charts + output/analysis_report.md
src/samples.py    # 8 fictional messages (4 attacks, 1 ambiguous, 3 legitimate)
tests/            # test_analyzer.py (pins formulas), test_cli.py
```

## Commands

```bash
pip install -r requirements.txt
python main.py                                     # 8 samples -> charts + report in output/
python main.py --text "URGENT: verify your account immediately."
python main.py --file suspicious_email.txt --json  # JSON, single input only
python main.py --no-charts
pytest -q                                          # 24 tests, offline
```

## Gotchas

- Scoring (README "Scoring methodology") is pinned by `tests/test_analyzer.py`: vector base = `min(matches / max(0.15 × list_size, 1) × 100, 90)` × weight; composite = mean of top 3, ×1.10/1.20/1.30 for 3/4/5+ active vectors (score > 12), ×(1 + 0.2 × VADER neg) when neg > 0.3, cap 100. Bands: LOW < 25 ≤ MEDIUM < 50 ≤ HIGH < 75 ≤ CRITICAL. Change code, tests and README together.
- Matches are distinct whole words/phrases per vector (repeats count once; "won" ≠ "wonderful").
- Zero-width / bidi / soft-hyphen characters are removed before matching and raise their own red flag.
- The false-intimacy flag needs ≥ 2 familiarity cues.
- Weights/thresholds are hand-tuned design choices (in `src/taxonomy.py`, `src/analyzer.py`), not empirical.

## Conventions (shared across the owner's portfolio repos)

- Plain Python 3.11+ CLI: `main.py` (argparse) at the root, logic in `src/`, tests in `tests/`. No package build, no lint/format config.
- `pytest.ini` sets `testpaths = tests` and `pythonpath = .`, so run `pytest` from the repo root.
- CI (`.github/workflows/tests.yml`): `pip install -r requirements.txt` + `pytest -q` on Python 3.11 and 3.12, on every push and PR. Tests must stay offline (no network, no API keys).
- Generated files go to `output/` (gitignored). Never commit them.
- README is English with a Spanish `> **Resumen:**` blurb at the top; it documents formulas and limitations precisely. When you change behaviour, update the README in the same change (tests often pin the documented formulas).
- Be honest about scope: the README's "Limitations" section is part of the product. Don't add claims the code doesn't support.

## Memoria persistente (Graphiti MCP)
Este proyecto usa el connector **Graphiti** (memoria en grafo compartida entre sesiones).
- `group_id` de este repo: `phishing-psychology-analyzer`. Datos del usuario y transversales: `neckr0ik-global`.
- Al empezar una tarea: busca contexto con `search_memory_facts` y `search_nodes` usando `group_ids: ["phishing-psychology-analyzer", "neckr0ik-global"]`.
- Al terminar algo relevante (decisión de arquitectura, convención nueva, bug resuelto y su causa, preferencia del usuario, estado de un despliegue): guárdalo con `add_memory` (`group_id: "phishing-psychology-analyzer"`, `source: "text"`) con un nombre descriptivo.
- Nunca guardes secretos, API keys, tokens, contraseñas ni datos personales sensibles.
- Si Graphiti no está disponible en la sesión, continúa normalmente.
