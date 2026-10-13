"""
Report and visualization generator for phishing psychology analysis.
"""

from __future__ import annotations
import os
import re
from datetime import datetime
from typing import List

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

from .analyzer import AnalysisResult
from .taxonomy import MANIPULATION_VECTORS, RISK_LEVELS

OUTPUT_DIR = "output"


def _ensure_dir(filename: str) -> None:
    os.makedirs(os.path.dirname(filename) or ".", exist_ok=True)


# ── Per-sample radar chart ────────────────────────────────────────────────────

def plot_radar(result: AnalysisResult, filename: str = None) -> str:
    labels = [v.label for v in result.vectors.values()]
    scores = [v.score for v in result.vectors.values()]
    colors = [v.color for v in result.vectors.values()]
    n = len(labels)

    angles = np.linspace(0, 2 * np.pi, n, endpoint=False).tolist()
    scores_plot = scores + [scores[0]]
    angles += angles[:1]

    fig, ax = plt.subplots(figsize=(7, 7), subplot_kw=dict(polar=True))
    fig.patch.set_facecolor("#0D1117")
    ax.set_facecolor("#161B22")

    ax.plot(angles, scores_plot, color="#E74C3C", linewidth=2)
    ax.fill(angles, scores_plot, color="#E74C3C", alpha=0.25)

    # Gridlines
    ax.set_ylim(0, 100)
    ax.set_yticks([25, 50, 75, 100])
    ax.set_yticklabels(["25", "50", "75", "100"], color="#8B949E", fontsize=7)
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(labels, color="#C9D1D9", fontsize=8, wrap=True)
    ax.grid(color="#30363D", linewidth=0.8)
    ax.spines["polar"].set_color("#30363D")

    risk = result.risk_level
    title_color = risk["color"]
    ax.set_title(
        f"{result.label}\n"
        f"Composite: {result.composite_score:.0f}/100  [{risk['icon']}]",
        color=title_color, fontsize=11, fontweight="bold", pad=20,
    )

    if filename is None:
        safe = re.sub(r"[^a-z0-9]+", "_", result.label.lower()).strip("_")[:30]
        filename = os.path.join(OUTPUT_DIR, f"radar_{safe}.png")
    _ensure_dir(filename)
    plt.tight_layout()
    plt.savefig(filename, dpi=130, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close()
    return filename


# ── Comparison bar chart (batch) ─────────────────────────────────────────────

def plot_comparison(results: List[AnalysisResult], filename: str = None) -> str:
    labels = [r.label[:30] for r in results]
    scores = [r.composite_score for r in results]
    bar_colors = [r.risk_level["color"] for r in results]

    fig, ax = plt.subplots(figsize=(10, 5))
    fig.patch.set_facecolor("#0D1117")
    ax.set_facecolor("#161B22")

    bars = ax.barh(labels, scores, color=bar_colors, height=0.55, edgecolor="#30363D")

    for bar, score, result in zip(bars, scores, results):
        ax.text(
            min(score + 1, 97), bar.get_y() + bar.get_height() / 2,
            f"{score:.0f}  [{result.risk_level['icon']}]",
            va="center", ha="left", color="#C9D1D9", fontsize=9,
        )

    ax.set_xlim(0, 105)
    ax.set_xlabel("Manipulation Score (0-100)", color="#8B949E", fontsize=9)
    ax.set_title("Manipulation Risk Comparison", color="#E6EDF3", fontsize=12, fontweight="bold")
    ax.tick_params(colors="#8B949E")
    for spine in ax.spines.values():
        spine.set_color("#30363D")

    # Risk level legend
    patches = [mpatches.Patch(color=v["color"], label=f"{k}: {v['label']}") for k, v in RISK_LEVELS.items()]
    ax.legend(handles=patches, loc="lower right", fontsize=8,
              facecolor="#161B22", edgecolor="#30363D", labelcolor="#C9D1D9")

    ax.axvline(x=25, color="#27AE60", linestyle="--", linewidth=0.8, alpha=0.5)
    ax.axvline(x=50, color="#F39C12", linestyle="--", linewidth=0.8, alpha=0.5)
    ax.axvline(x=75, color="#E67E22", linestyle="--", linewidth=0.8, alpha=0.5)

    if filename is None:
        filename = os.path.join(OUTPUT_DIR, "comparison_all.png")
    _ensure_dir(filename)
    plt.tight_layout()
    plt.savefig(filename, dpi=130, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close()
    return filename


# ── Vector heatmap ────────────────────────────────────────────────────────────

def plot_heatmap(results: List[AnalysisResult], filename: str = None) -> str:
    sample_labels = [r.label[:25] for r in results]
    vector_labels = [v["label"].split(" / ")[0] for v in MANIPULATION_VECTORS.values()]
    vector_ids    = list(MANIPULATION_VECTORS.keys())

    matrix = np.array([
        [r.vectors[vid].score for vid in vector_ids]
        for r in results
    ])

    fig, ax = plt.subplots(figsize=(12, max(4, len(results) * 0.7 + 2)))
    fig.patch.set_facecolor("#0D1117")
    ax.set_facecolor("#161B22")

    im = ax.imshow(matrix, cmap="RdYlGn_r", aspect="auto", vmin=0, vmax=100)

    for i in range(len(sample_labels)):
        for j in range(len(vector_labels)):
            val = matrix[i, j]
            text_color = "white" if val > 55 else "#C9D1D9"
            ax.text(j, i, f"{val:.0f}", ha="center", va="center",
                    color=text_color, fontsize=8)

    ax.set_xticks(range(len(vector_labels)))
    ax.set_xticklabels(vector_labels, rotation=35, ha="right", color="#C9D1D9", fontsize=8)
    ax.set_yticks(range(len(sample_labels)))
    ax.set_yticklabels(sample_labels, color="#C9D1D9", fontsize=9)

    plt.colorbar(im, ax=ax, label="Manipulation Score", fraction=0.03, pad=0.02)
    ax.set_title("Manipulation Vector Heatmap", color="#E6EDF3", fontsize=12, fontweight="bold", pad=12)

    if filename is None:
        filename = os.path.join(OUTPUT_DIR, "heatmap_vectors.png")
    _ensure_dir(filename)
    plt.tight_layout()
    plt.savefig(filename, dpi=130, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close()
    return filename


# ── Markdown report ───────────────────────────────────────────────────────────

def write_report(results: List[AnalysisResult], filename: str = None) -> str:
    if filename is None:
        filename = os.path.join(OUTPUT_DIR, "analysis_report.md")

    lines = [
        "# Phishing Psychology Analysis Report",
        f"*Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}*",
        "",
        "> Heuristic keyword analysis of persuasion pressure. A high score means the text "
        "leans on several social-engineering levers; it does not prove the message is malicious, "
        "and a low score does not prove it is safe (check sender, links and headers too).",
        "",
        "---",
        "",
        "## Summary",
        "",
        "| Sample | Score | Risk Level | Dominant Vectors |",
        "|:---|:---:|:---:|:---|",
    ]

    for r in results:
        dominant_str = ", ".join(
            MANIPULATION_VECTORS[vid]["label"].split(" / ")[0]
            for vid in r.dominant_vectors
        ) or "None"
        lines.append(
            f"| {r.label} | {r.composite_score:.0f}/100 | "
            f"**{r.risk_level['label']}** | {dominant_str} |"
        )

    lines += ["", "---", ""]

    for r in results:
        risk = r.risk_level
        lines += [
            f"## {r.label}",
            f"**Risk Level:** {risk['label']}  |  **Score:** {r.composite_score:.0f}/100  "
            f"|  **Word Count:** {r.word_count}",
            "",
        ]

        if r.flags:
            lines.append("**Red Flags:**")
            for flag in r.flags:
                lines.append(f"- {flag}")
            lines.append("")

        active = [v for v in r.vectors.values() if v.score > 10]
        active.sort(key=lambda v: v.score, reverse=True)

        if active:
            lines.append("**Active Manipulation Vectors:**")
            lines.append("")
            lines.append("| Vector | Score | Cognitive Bias Exploited | Matched Keywords | ATT&CK context |")
            lines.append("|:---|:---:|:---|:---|:---|")
            for v in active:
                kws = ", ".join(f"`{kw}`" for kw in v.matched_keywords[:5])
                mitre = MANIPULATION_VECTORS[v.vector_id]["mitre_ref"]
                lines.append(f"| {v.label} | {v.score:.0f} | {v.bias} | {kws} | {mitre} |")
            lines.append("")

        lines += [
            f"**VADER Sentiment:** pos={r.vader_scores['pos']:.2f}  "
            f"neg={r.vader_scores['neg']:.2f}  "
            f"neu={r.vader_scores['neu']:.2f}  "
            f"compound={r.vader_scores['compound']:.2f}",
            "",
            "---",
            "",
        ]

    _ensure_dir(filename)
    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return filename
