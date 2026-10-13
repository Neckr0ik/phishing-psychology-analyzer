import pytest

from src.analyzer import analyze, analyze_batch, find_keywords, _composite, VectorResult
from src.samples import SAMPLES
from src.taxonomy import MANIPULATION_VECTORS, get_risk_level


def test_whole_word_matching():
    assert find_keywords("a wonderful administrator in a pineapple farm", ["won", "admin", "apple"]) == []
    assert find_keywords("you won! contact the admin", ["won", "admin"]) == ["won", "admin"]
    assert find_keywords("act now, act now", ["act now"]) == ["act now"]  # distinct, no stuffing


def test_risk_level_boundaries():
    assert get_risk_level(0)["id"] == "LOW"
    assert get_risk_level(24.9)["id"] == "LOW"
    assert get_risk_level(25)["id"] == "MEDIUM"
    assert get_risk_level(50)["id"] == "HIGH"
    assert get_risk_level(75)["id"] == "CRITICAL"
    assert get_risk_level(100)["id"] == "CRITICAL"


def test_benign_text_is_low():
    r = analyze("Hello team, the meeting notes from Tuesday are attached. Have a good weekend.")
    assert r.composite_score < 25 and r.risk_level["id"] == "LOW"
    assert r.flags == []


def test_classic_phish_is_critical_with_flags():
    r = analyze("URGENT: your account has been compromised. Our security team detected unauthorized "
                "access. Verify immediately or your account will be suspended within 24 hours.")
    assert r.risk_level["id"] == "CRITICAL"
    assert any("Authority + threat" in f for f in r.flags)
    assert {"urgency", "fear_threat"} <= set(r.dominant_vectors)


def test_samples_rank_scams_above_legitimate():
    by_label = {r.label: r.composite_score for r in analyze_batch(SAMPLES)}
    scams = ["Spear Phishing (CEO Fraud)", "Account Threat Email", "Prize Scam", "Tech Support Scam"]
    legit = ["Bank Notification (legitimate)", "HR Newsletter (legitimate)"]
    assert min(by_label[s] for s in scams) > max(by_label[l] for l in legit)
    assert all(by_label[l] < 25 for l in legit)


def test_scores_bounded():
    for r in analyze_batch(SAMPLES):
        assert 0 <= r.composite_score <= 100
        assert set(r.vectors) == set(MANIPULATION_VECTORS)
        assert all(0 <= v.score <= 100 for v in r.vectors.values())


def _vectors(scores):
    return {f"v{i}": VectorResult(f"v{i}", "x", s, [], "", "", "") for i, s in enumerate(scores)}


@pytest.mark.parametrize("scores,expected", [
    ([30, 30, 30, 0, 0], 33.0),          # 3 active -> x1.10
    ([30, 30, 30, 30, 0], 36.0),         # 4 active -> x1.20
    ([30, 30, 30, 30, 30], 39.0),        # 5 active -> x1.30
    ([30, 0, 0, 0, 0], 10.0),            # 1 active -> mean of top 3, no boost
])
def test_multi_vector_amplification_matches_readme(scores, expected):
    assert _composite(_vectors(scores), vader_neg=0.0) == expected


def test_vader_negativity_amplifies():
    assert _composite(_vectors([30, 0, 0]), vader_neg=0.5) == 11.0
