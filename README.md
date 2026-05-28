# Phishing Psychology Analyzer

**Core question:** What makes a phishing email work — and can we detect it before a human falls for it?

This tool analyzes text for the eight psychological manipulation vectors used in social engineering attacks. It maps detected tactics to the cognitive biases they exploit, produces a composite risk score, and generates visualizations for security awareness training and threat triage.

---

## Sample output

```
Phishing Psychology Analyzer
============================================================

  Critical: Spear Phishing (CEO Fraud)
  [################    ] 83/100  [CRIT] CRITICAL RISK
  Dominant vectors: Authority / Impersonation | Urgency / Time Pressure | Fear / Threat Appraisal
  [!] Authority + threat combination — classic spear-phishing pattern
  [!] Artificial urgency — suppresses System 2 deliberation
  [!] CRITICAL: Multiple coordinated manipulation vectors detected

  Low: Legitimate Bank Notification
  [###                 ] 8/100  [LOW ] LOW RISK
  Dominant vectors: Familiarity / False Intimacy
```

---

## The psychology behind social engineering

Most security tools detect phishing by analyzing URLs, headers, or sender reputation. This tool operates one layer deeper — at the **cognitive level**. Every effective social engineering attack exploits the gap between how humans *think* they make decisions and how they *actually* make them.

| Manipulation Vector | Cognitive Bias Exploited | Why It Works |
|:---|:---|:---|
| **Urgency / Time Pressure** | Loss Aversion + Availability Heuristic | Compressed time horizons prevent System 2 (deliberate) reasoning |
| **Authority / Impersonation** | Authority Bias + Halo Effect | Institutional trust cues suppress skeptical evaluation |
| **Fear / Threat Appraisal** | Negativity Bias + Amygdala Activation | Threat response elevates cortisol, narrowing analytical processing |
| **Scarcity / Exclusivity** | Scarcity Heuristic + FOMO | Perceived rarity elevates subjective value and accelerates commitment |
| **Reciprocity / Reward** | Reciprocity Norm + Variable Reward | Unsolicited gifts create social obligation to comply |
| **Social Proof / Consensus** | Bandwagon Effect | Perceived group consensus normalizes the requested action |
| **Familiarity / False Intimacy** | Mere Exposure Effect | Contextual mirroring creates false sense of prior relationship |
| **Curiosity / Information Gap** | Zeigarnik Effect | Partial information creates aversive arousal compelling gap-closure |

*The most dangerous attacks combine three or more vectors simultaneously — what Cialdini (1984) calls "influence stacking," where compliance triggers compound each other's effect.*

---

## Quick start

```bash
git clone https://github.com/Neckr0ik/phishing-psychology-analyzer.git
cd phishing-psychology-analyzer
pip install -r requirements.txt
python main.py
```

Analyze your own text:

```bash
python main.py --text "URGENT: Your account has been compromised. Verify immediately."
```

Runtime: ~3 seconds for the full 8-sample batch.

---

## Architecture

```
phishing-psychology-analyzer/
├── main.py               # CLI entry point, batch runner
├── src/
│   ├── taxonomy.py       # 8 manipulation vectors + MITRE ATT&CK refs + bias mappings
│   ├── analyzer.py       # Scoring engine: keyword coverage + VADER + multi-vector amplification
│   ├── reporter.py       # Radar charts, comparison bar, heatmap, markdown report
│   └── samples.py        # 8 sample texts spanning LOW to CRITICAL risk
└── output/               # Generated charts and report (git-ignored)
```

---

## Scoring methodology

For each vector:

1. **Keyword coverage** — distinct keywords found ÷ total keywords in vector (prevents stuffing)
2. **Weight multiplier** — fear/threat vectors carry higher weights (empirically more effective)
3. **Multi-vector amplification** — 3+ active vectors trigger a 20–35% composite boost
4. **VADER sentiment correlation** — high negative sentiment amplifies threat-based vector scores

```python
# Core formula
coverage = distinct_keywords_found / total_keywords_in_vector
base_score = min((coverage / 0.15) * 100, 90)
vector_score = min(base_score * weight, 100)

# Multi-vector amplification
if active_vectors >= 4:
    composite *= 1.35
elif active_vectors >= 3:
    composite *= 1.20
```

---

## Output charts

| Chart | Description |
|---|---|
| `radar_*.png` | Per-sample radar chart across all 8 manipulation vectors |
| `comparison_all.png` | Horizontal bar chart ranking all samples by composite score |
| `heatmap_vectors.png` | Matrix heatmap: samples × vectors with score values |
| `analysis_report.md` | Full markdown report with red flags, bias mappings, and matched keywords |

---

## References

- Cialdini, R. B. (1984). *Influence: The Psychology of Persuasion.* Harper Business.
- Kahneman, D. (2011). *Thinking, Fast and Slow.* Farrar, Straus and Giroux.
- Loewenstein, G. (1994). The psychology of curiosity: A review and reinterpretation. *Psychological Bulletin, 116*(1), 75–98.
- MITRE ATT&CK Framework. (2024). *Enterprise Techniques.* attack.mitre.org

---

## Skills demonstrated

`Python` · `Behavioral Psychology` · `Cybersecurity (MITRE ATT&CK)` · `NLP (VADER)` · `Cognitive Bias Analysis` · `Social Engineering Defense` · `Matplotlib` · `Security Awareness`

---

## License

MIT © 2026 Giovanni Oliveira
