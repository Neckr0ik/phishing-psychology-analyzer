# Phishing Psychology Analyzer

> **Resumen:** Analiza un texto (correo, SMS, mensaje) y detecta ocho palancas psicológicas típicas de la ingeniería social: urgencia, autoridad, miedo, escasez, reciprocidad, prueba social, falsa familiaridad y curiosidad. Relaciona cada una con el sesgo cognitivo que explota y calcula un puntaje heurístico de presión persuasiva. No es un detector de phishing: complementa, no sustituye, la revisión de remitente, enlaces y encabezados.

*Part of Giovanni Oliveira's Hybrid Intelligence portfolio — see https://github.com/Neckr0ik*

**Core question:** what psychological levers does a message pull, and how many does it stack at once?

Most phishing filters look at URLs, headers and sender reputation. This tool looks at the **wording**. It detects eight manipulation vectors, maps each to the cognitive bias it exploits and to the closest MITRE ATT&CK technique, and combines them into a 0–100 composite score with red flags. The intended uses are security-awareness training and helping a human triage suspicious messages.

---

## Sample output

Real output of `python main.py --no-charts` (excerpt):

```
  Spear Phishing (CEO Fraud)
  [##################  ] 92/100  [CRIT] CRITICAL RISK
  Dominant vectors: Urgency / Time Pressure | Fear / Threat Appraisal | Scarcity / Exclusivity
  [!] Authority + threat combination — classic spear-phishing pattern
  [!] CRITICAL: Multiple coordinated manipulation vectors detected

  Marketing Email (legitimate)
  [###########         ] 55/100  [HIGH] HIGH RISK
  Dominant vectors: Scarcity / Exclusivity | Social Proof / Consensus

  Bank Notification (legitimate)
  [####                ] 22/100  [LOW] LOW RISK
```

The legitimate marketing email scores HIGH because it really does use scarcity and social proof. **The score measures persuasion pressure, not malice.**

---

## The eight vectors

| Vector | Cognitive bias exploited | ATT&CK context |
|:---|:---|:---|
| **Urgency / Time Pressure** | Loss aversion, availability heuristic | T1566, T1598 |
| **Authority / Impersonation** | Authority bias, halo effect | T1656, T1585 |
| **Fear / Threat Appraisal** | Negativity bias, loss aversion | T1566 |
| **Scarcity / Exclusivity** | Scarcity heuristic, FOMO (Brock, 1968) | T1566 |
| **Reciprocity / Reward Baiting** | Reciprocity norm (Cialdini, 1984) | T1566 |
| **Social Proof / Consensus** | Social proof, bandwagon effect | T1566 |
| **Familiarity / False Intimacy** | Mere-exposure effect, in-group bias | T1585.001, T1656 |
| **Curiosity / Information Gap** | Information gap (Loewenstein, 1994) | T1566, T1204 |

ATT&CK catalogues adversary techniques. It does not classify psychological levers, so the IDs above are the closest techniques for the delivery channel, given for context. They are not an official ATT&CK mapping.

---

## Scoring methodology

The code in `src/analyzer.py` does the following:

1. **Keyword matching.** Distinct whole-word/phrase matches per vector, so repeating "act now" five times counts once, and "won" does not match "wonderful".
2. **Vector score.** `base = min(matches / (0.15 × list_size) × 100, 90)`, then `score = min(base × weight, 100)`. The weights (fear 1.8, urgency 1.5, authority 1.4 …) are design choices, not empirical estimates.
3. **Composite.** The mean of the top 3 vectors, multiplied by **1.10 / 1.20 / 1.30** when 3 / 4 / 5+ vectors are active (score > 12), and by `1 + 0.2 × VADER_neg` when VADER negativity exceeds 0.3. It is capped at 100.
4. **Risk bands.** LOW < 25 ≤ MEDIUM < 50 ≤ HIGH < 75 ≤ CRITICAL.

The tests in `tests/test_analyzer.py` pin these formulas, so this section and the code stay in sync.

---

## Install, run, test

```bash
git clone https://github.com/Neckr0ik/phishing-psychology-analyzer.git
cd phishing-psychology-analyzer
pip install -r requirements.txt

python main.py                                     # 8 fictional samples -> charts + report in output/
python main.py --text "URGENT: verify your account immediately."
python main.py --file suspicious_email.txt --json  # JSON for pipelines / SOAR triage notes
python main.py --no-charts

pytest -q                                          # offline test suite
```

Python 3.11+. CI runs the tests on Python 3.11 and 3.12 (`.github/workflows/tests.yml`).

| Output | Description |
|---|---|
| `radar_*.png` | Per-sample radar across the 8 vectors |
| `comparison_all.png` | All samples ranked by composite score |
| `heatmap_vectors.png` | Samples × vectors matrix |
| `analysis_report.md` | Red flags, biases, matched keywords and ATT&CK context per sample |

## Architecture

```
phishing-psychology-analyzer/
├── main.py           # CLI: batch, --text, --file, --json
├── src/
│   ├── taxonomy.py   # 8 vectors, keywords, biases, ATT&CK context, risk bands
│   ├── analyzer.py   # whole-word matching, vector scores, composite, red flags
│   ├── reporter.py   # charts + markdown report
│   └── samples.py    # 8 fictional messages (4 attacks, 1 ambiguous, 3 legitimate)
└── tests/
```

## Limitations

- **Not a phishing classifier.** It has not been trained or evaluated on a labelled phishing corpus, so no accuracy, precision or recall numbers exist for it. A well-written phish with few trigger words can score LOW.
- **False positives on marketing.** Promotions use scarcity, social proof and urgency by design.
- **English only.** The keyword lists and VADER are English. Spanish and Portuguese phishing (common in LATAM) is not covered.
- **Wording only.** Sender, links, attachments and headers are ignored. Use it next to technical controls, never instead of them.
- **Hand-tuned weights.** All weights and thresholds are editable in `src/taxonomy.py` and `src/analyzer.py`.

## References

- Brock, T. C. (1968). Implications of commodity theory for value change. In *Psychological Foundations of Attitudes*. Academic Press.
- Cialdini, R. B. (1984). *Influence: The Psychology of Persuasion.* William Morrow.
- Kahneman, D. (2011). *Thinking, Fast and Slow.* Farrar, Straus and Giroux.
- Loewenstein, G. (1994). The psychology of curiosity: A review and reinterpretation. *Psychological Bulletin, 116*(1), 75–98.
- Sherif, M. (1936). *The Psychology of Social Norms.* Harper.
- MITRE ATT&CK, Enterprise techniques: attack.mitre.org

## License

MIT © 2026 Giovanni Oliveira
