"""
Manipulation Analysis Engine
Scores text against each manipulation vector using keyword coverage and VADER sentiment.
"""

from __future__ import annotations
from dataclasses import dataclass
from functools import lru_cache
from typing import Dict, List
import re
import unicodedata

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
    hidden_characters: int = 0        # invisible format characters found inside words


_QUOTE_FOLD = str.maketrans({"\u2019": "'", "\u2018": "'", "\u201c": '"', "\u201d": '"'})


def _is_invisible(ch: str) -> bool:
    # Unicode "format" characters: zero-width space/joiner/non-joiner, soft hyphen, BOM,
    # bidi overrides. They render as nothing but break naive keyword matching.
    return unicodedata.category(ch) == "Cf"


def count_hidden_characters(text: str) -> int:
    """Invisible format characters placed inside words (e.g. "URG\u200bENT") or bidi
    controls anywhere. A zero-width joiner between emoji is normal and not counted."""
    n = 0
    for i, ch in enumerate(text):
        if not _is_invisible(ch):
            continue
        prev = text[i - 1] if i > 0 else ""
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if ch != "\u200d" or prev.isalnum() or nxt.isalnum():
            n += 1
    return n


def clean_text(text: str) -> str:
    """NFKC-normalise, drop invisible format characters and fold curly quotes (case kept)."""
    text = unicodedata.normalize("NFKC", text)
    text = "".join(ch for ch in text if not _is_invisible(ch))
    return text.translate(_QUOTE_FOLD)


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", clean_text(text).lower().strip())


@lru_cache(maxsize=None)
def _pattern(keyword: str) -> "re.Pattern[str]":
    # Whole-word / whole-phrase match: "won" must not match "wonderful", "admin" not "administrator".
    return re.compile(rf"(?<!\w){re.escape(keyword.lower())}(?!\w)")


def find_keywords(text: str, keywords: List[str]) -> List[str]:
    """Distinct keywords (in list order) present in `text` as whole words/phrases."""
    return [kw for kw in dict.fromkeys(k.lower() for k in keywords) if _pattern(kw).search(text)]


def _score_vector(text: str, vector_id: str) -> VectorResult:
    vec = MANIPULATION_VECTORS[vector_id]
    # Distinct keywords only, so repeating "act now" five times counts once.
    matched = find_keywords(text, vec["keywords"])

    # Base score: matching 15% of a vector's keywords (about 3-5 distinct cues) reaches
    # the 90-point cap; the vector weight then scales it (final score capped at 100).
    # The divisor is at least 1 so a very short keyword list cannot divide by < 1.
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

    # Base score: mean of top-3 vectors (a design choice). Attacks rarely use all 8 levers,
    # so a full mean would dilute focused messages that lean hard on two or three.
    top3_avg = sum(scores[:3]) / 3

    # Multi-vector amplification (a design choice): messages that stack several levers at
    # once may put more pressure on the reader, so the score is boosted.
    active_count = sum(1 for s in scores if s > 12)
    if active_count >= 5:
        top3_avg = min(top3_avg * 1.30, 100)
    elif active_count >= 4:
        top3_avg = min(top3_avg * 1.20, 100)
    elif active_count >= 3:
        top3_avg = min(top3_avg * 1.10, 100)

    # High VADER negativity may add to the pressure of threat-based wording: small boost.
    if vader_neg > 0.3:
        top3_avg = min(top3_avg * (1 + vader_neg * 0.20), 100)

    return round(top3_avg, 1)


FAMILIARITY_MIN_CUES = 2   # one "your account" alone is normal in legitimate mail


def _build_flags(vectors: Dict[str, VectorResult], vader: dict, composite: float,
                 hidden_chars: int = 0) -> List[str]:
    flags = []
    if hidden_chars:
        flags.append(f"Invisible characters inside words ({hidden_chars}) — a common trick to "
                     "slip trigger words past filters")
    if vectors["fear_threat"].score > 25:
        flags.append("Threat-based coercion detected — may discourage careful evaluation")
    if vectors["urgency"].score > 25:
        flags.append("Artificial urgency — may push a reply before deliberate (System 2) thinking")
    if vectors["authority"].score > 20 and vectors["fear_threat"].score > 20:
        flags.append("Authority + threat combination — classic spear-phishing pattern")
    if vectors["reciprocity"].score > 25:
        flags.append("Unsolicited reward — may invoke a sense of obligation (reciprocity)")
    if vectors["curiosity"].score > 25:
        flags.append("Information gap — may prompt a click before critical evaluation")
    if (vectors["familiarity"].score > 20
            and len(vectors["familiarity"].matched_keywords) >= FAMILIARITY_MIN_CUES):
        flags.append("False intimacy — implied prior relationship that may lower the reader's guard")
    if vader["neg"] > 0.4:
        flags.append(f"High negative affect (VADER neg={vader['neg']:.2f}) — fear-laden wording")
    if composite > 75:
        flags.append("CRITICAL: Multiple coordinated manipulation vectors detected")
    return flags


def analyze(text: str, label: str = "Input Text") -> AnalysisResult:
    hidden = count_hidden_characters(text)
    normalized = _normalize(text)
    words = normalized.split()
    word_count = len(words)

    vader = _vader.polarity_scores(clean_text(text))
    vectors = {vid: _score_vector(normalized, vid) for vid in MANIPULATION_VECTORS}
    composite = _composite(vectors, vader["neg"])
    risk = get_risk_level(composite)

    dominant = sorted(vectors.values(), key=lambda v: v.score, reverse=True)
    dominant_ids = [v.vector_id for v in dominant[:3] if v.score > 5]

    flags = _build_flags(vectors, vader, composite, hidden)

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
        hidden_characters=hidden,
    )


def analyze_batch(texts: Dict[str, str]) -> List[AnalysisResult]:
    return [analyze(text, label=label) for label, text in texts.items()]
