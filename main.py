"""
Phishing Psychology Analyzer
Run:  python main.py
Run on custom text:  python main.py --text "Your text here"
Run on a file:        python main.py --file suspicious_email.txt --json

Analyzes text for psychological manipulation vectors used in social engineering.
Maps detected tactics to the cognitive biases they exploit, and outputs a
heuristic pressure score, red flags, and visualizations.
"""

import argparse
import json
import sys
from src.samples import SAMPLES
from src.analyzer import analyze, analyze_batch
from src.reporter import plot_radar, plot_comparison, plot_heatmap, write_report
from src.taxonomy import MANIPULATION_VECTORS


def print_result(result):
    risk = result.risk_level
    bar = "[" + "#" * int(result.composite_score / 5) + " " * (20 - int(result.composite_score / 5)) + "]"

    print(f"\n  {result.label}")
    print(f"  {bar} {result.composite_score:.0f}/100  [{risk['icon']}] {risk['label'].upper()}")
    print(f"  VADER: neg={result.vader_scores['neg']:.2f}  pos={result.vader_scores['pos']:.2f}"
          f"  compound={result.vader_scores['compound']:.2f}")

    if result.dominant_vectors:
        dominant_labels = [
            MANIPULATION_VECTORS[vid]["label"] for vid in result.dominant_vectors
        ]
        print(f"  Dominant vectors: {' | '.join(dominant_labels)}")

    if result.flags:
        for flag in result.flags:
            print(f"  [!] {flag}")


def to_dict(result) -> dict:
    return {
        "label": result.label,
        "composite_score": result.composite_score,
        "risk_level": result.risk_level["id"],
        "dominant_vectors": result.dominant_vectors,
        "flags": result.flags,
        "hidden_characters": result.hidden_characters,
        "vectors": {vid: {"score": v.score, "matched_keywords": v.matched_keywords,
                          "bias": v.bias, "mitre_ref": MANIPULATION_VECTORS[vid]["mitre_ref"]}
                    for vid, v in result.vectors.items()},
        "vader": result.vader_scores,
        "word_count": result.word_count,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Phishing Psychology Analyzer")
    src = parser.add_mutually_exclusive_group()
    src.add_argument("--text", "-t", type=str, help="Analyze a custom text string")
    src.add_argument("--file", "-f", type=str, help="Analyze the text of a file (e.g. a saved email body)")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON (single input only)")
    parser.add_argument("--no-charts", action="store_true", help="Skip chart generation")
    args = parser.parse_args(argv)

    if args.file is not None:
        try:
            with open(args.file, encoding="utf-8", errors="replace") as f:
                args.text = f.read()
        except OSError as e:
            parser.error(f"cannot read --file {args.file}: {e.strerror or e}")

    if args.text is not None and not args.text.strip():
        parser.error(f"{'--file ' + args.file if args.file is not None else '--text'} is empty; nothing to analyze")

    if args.json:
        if args.text is None:
            parser.error("--json works on one message: add --text \"...\" or --file PATH "
                         "(the bundled samples have no JSON output)")
        print(json.dumps(to_dict(analyze(args.text, label=args.file or "Custom Input")), indent=2))
        return 0

    print("Phishing Psychology Analyzer")
    print("=" * 60)
    print("Cognitive bias exploitation detector for social engineering")
    print("=" * 60)

    if args.text is not None:
        result = analyze(args.text, label=args.file or "Custom Input")
        print_result(result)
        if not args.no_charts:
            f = plot_radar(result)
            print(f"\n  Chart saved -> {f}")
        return 0

    print("\n[1/3] Analyzing sample texts...")
    results = analyze_batch(SAMPLES)

    print()
    for result in results:
        print_result(result)

    if not args.no_charts:
        print("\n[2/3] Generating visualizations...")
        for result in results:
            plot_radar(result)

        comp_f = plot_comparison(results)
        heat_f = plot_heatmap(results)
        print(f"  Comparison chart  -> {comp_f}")
        print(f"  Vector heatmap    -> {heat_f}")

    print("\n[3/3] Writing report...")
    report_f = write_report(results)
    print(f"  Markdown report   -> {report_f}")

    print()
    print("=" * 60)
    print("SAMPLE RISK BREAKDOWN")
    print("=" * 60)

    risk_groups = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
    for r in results:
        risk_groups[r.risk_level["id"]].append(r.label)

    for level, items in risk_groups.items():
        if items:
            print(f"  {level:8s}: {len(items)} sample(s)")

    print()
    print("HOW TO READ THIS")
    print("-" * 60)
    print("The top-scoring samples stack several levers at once (urgency, fear,")
    print("authority, reward). Legitimate marketing uses some of the same levers,")
    print("so the score measures persuasion pressure, not proof of malice.")
    print("Always combine it with sender, link and header checks.")
    print()
    print("All charts and report saved to output/")
    print()
    print("TIP: python main.py --text 'your message here'   analyze custom text")
    print("     python main.py --file email.txt --json      JSON for pipelines")
    return 0


if __name__ == "__main__":
    sys.exit(main())
