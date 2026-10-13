"""
Manipulation Analysis Engine
Scores text against each manipulation vector using keyword coverage and VADER sentiment.
"""

from __future__ import annotations
from dataclasses import dataclass
from functools import lru_cache
from typing import Dict, List, Tuple
import re

from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer
from .taxonomy import MANIPULATION_VECTORS, get_risk_level

_vader = SentimentIntensityAnalyzer()


@dataclass
class VectorResult:
    vector_id: str
    label: str
    score: float                      # 0–100
    matched_keywords: List[str]
    bias: str
    mechanism: str
    color: str


@dataclass
class AnalysisResult:
    text: str
    label: str
    composite_score: float            # 0–100
    risk_level: dict
    vectors: Dict[str, VectorResult]
    dominant_vectors: List[str]       # top 3 by score
    vader_scores: dict
    word_count: int
    flags: List[str]                  # qualitative red flags


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text.lower().strip())


@lru_cache(maxsize=None)
def _pattern(keyword: str) -> "re.Pattern[str]":
    # Whole-word / whole-phrase match: "won" must not match "wonderful", "admin" not "administrator".
    return re.compile(rf"(?<!\w){re.escape(keyword.lower())}(?!\w)")


def find_keywords(text: str, keywords: List[str]) -> List[str]:
    """Distinct keywords (in list order) present in `text` as whole words/phrases."""
    return [kw for kw in dict.fromkeys(k.lower() for k in keywords) if _pattern(kw).search(text)]


def _keyword_coverage(text: str, keywords: List[str]) -> Tuple[float, List[str]]:
    """
    Returns (coverage_ratio 0-1, matched_keyword_list).
    Coverage = distinct keywords found / total keywords in vector.
    Distinct-keyword scoring prevents keyword-stuffing inflation.
    """
    matched = find_keywords(text, keywords)
    coverage = len(matched) / max(len(keywords), 1)
    return coverage, matched


def _score_vector(text: str, vector_id: str) -> VectorResult:
    vec = MANIPULATION_VECTORS[vector_id]
    coverage, matched = _keyword_coverage(text, vec["keywords"])

    # Base score: matching 15% of a vector's keywords (about 3-5 distinct cues) reaches
    # the 90-point cap; the vector weight then scales it (final score capped at 100).
    base = min((len(matched) / max(len(vec["keywords"]) * 0.15, 1)) * 100, 90)

    score = min(base * vec["weight"], 100.0)
    return VectorResult(
        vector_id=vector_id,
        label=vec["label"],
        score=round(score, 1),
        matched_keywords=matched,
        bias=vec["bias"],
        mechanism=vec["mechanism"],
        color=vec["color"],
    )


def _composite(vector_results: Dict[str, VectorResult], vader_neg: float) -> float:
    scores = sorted([v.score for v in vector_results.values()], reverse=True)

    # Base score: mean of top-3 vectors. Phishing attacks rarely fire all 8 dimensions;
    # using the full mean penalizes focused attacks that are genuinely dangerous.
    top3_avg = sum(scores[:3]) / 3

    # Multi-vector amplification: coordinated attacks that fire 4+ vectors simultaneously
    # are disproportionately dangerous — the compliance triggers compound each other.
    active_count = sum(1 for s in scores if s > 12)
    if active_count >= 5:
        top3_avg = min(top3_avg * 1.30, 100)
    elif active_count >= 4:
        top3_avg = min(top3_avg * 1.20, 100)
    elif active_count >= 3:
        top3_avg = min(top3_avg * 1.10, 100)

    # VADER negative sentiment correlation: high negativity amplifies threat-based attacks.
    if vader_neg > 0.3:
        top3_avg = min(top3_avg * (1 + vader_neg * 0.20), 100)

    return round(top3_avg, 1)


def _build_flags(vectors: Dict[str, VectorResult], vader: dict, composite: float) -> List[str]:
    flags = []
    if vectors["fear_threat"].score > 25:
        flags.append("Threat-based coercion detected — bypasses rational evaluation")
    if vectors["urgency"].score > 25:
        flags.append("Artificial urgency — suppresses System 2 deliberation")
    if vectors["authority"].score > 20 and vectors["fear_threat"].score > 20:
        flags.append("Authority + threat combination — classic spear-phishing pattern")
    if vectors["reciprocity"].score > 25:
        flags.append("Unsolicited reward — activates reciprocity obligation")
    if vectors["curiosity"].score > 25:
        flags.append("Information gap — compels click before critical evaluation")
    if vectors["familiarity"].score > 20:
        flags.append("False intimacy — fabricated prior relationship to lower guard")
    if vader["neg"] > 0.4:
        flags.append(f"High negative affect (VADER neg={vader['neg']:.2f}) — fear arousal state")
    if composite > 75:
        flags.append("CRITICAL: Multiple coordinated manipulation vectors detected")
    return flags


def analyze(text: str, label: str = "Input Text") -> AnalysisResult:
    normalized = _normalize(text)
    words = normalized.split()
    word_count = len(words)

    vader = _vader.polarity_scores(text)
    vectors = {vid: _score_vector(normalized, vid) for vid in MANIPULATION_VECTORS}
    composite = _composite(vectors, vader["neg"])
    risk = get_risk_level(composite)

    dominant = sorted(vectors.values(), key=lambda v: v.score, reverse=True)
    dominant_ids = [v.vector_id for v in dominant[:3] if v.score > 5]

    flags = _build_flags(vectors, vader, composite)

    return AnalysisResult(
        text=text,
        label=label,
        composite_score=composite,
        risk_level=risk,
        vectors=vectors,
        dominant_vectors=dominant_ids,
        vader_scores=vader,
        word_count=word_count,
        flags=flags,
    )


def analyze_batch(texts: Dict[str, str]) -> List[AnalysisResult]:
    return [analyze(text, label=label) for label, text in texts.items()]
