"""
Phishing Psychology Analyzer
Run:  python main.py
Run on custom text:  python main.py --text "Your text here"

Analyzes text for psychological manipulation vectors used in social engineering.
Maps detected tactics to the cognitive biases they exploit, and outputs a
risk score, red flags, and publication-quality visualizations.
"""

import argparse
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


def main():
    parser = argparse.ArgumentParser(description="Phishing Psychology Analyzer")
    parser.add_argument("--text", "-t", type=str, help="Analyze a custom text string")
    parser.add_argument("--no-charts", action="store_true", help="Skip chart generation")
    args = parser.parse_args()

    print("Phishing Psychology Analyzer")
    print("=" * 60)
    print("Cognitive bias exploitation detector for social engineering")
    print("=" * 60)

    if args.text:
        result = analyze(args.text, label="Custom Input")
        print_result(result)
        if not args.no_charts:
            f = plot_radar(result)
            print(f"\n  Chart saved -> {f}")
        return

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
    print("KEY INSIGHT")
    print("-" * 60)
    print("The highest-risk samples combine fear_threat + urgency + authority,")
    print("a pattern Cialdini (1984) identifies as 'influence stacking' — where")
    print("multiple compliance triggers compound each other's effect, overwhelming")
    print("the target's ability to pause and apply critical evaluation.")
    print()
    print("All charts and report saved to output/")
    print()
    print("TIP: Run  python main.py --text 'your message here'  to analyze custom text.")


if __name__ == "__main__":
    main()
