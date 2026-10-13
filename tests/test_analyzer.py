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


PLAIN = ("URGENT: your account has been compromised. Our security team detected unauthorized "
         "access. Verify immediately or your account will be suspended within 24 hours.")


def test_invisible_characters_do_not_hide_keywords():
    hidden = PLAIN.replace("URGENT", "URG​ENT").replace("immediately", "imm​ediately") \
                  .replace("compromised", "compro­mised").replace("suspended", "sus‍pended")
    plain, obf = analyze(PLAIN), analyze(hidden)
    assert obf.composite_score >= plain.composite_score >= 75
    assert "urgent" in obf.vectors["urgency"].matched_keywords
    assert "immediately" in obf.vectors["urgency"].matched_keywords
    assert obf.hidden_characters == 4
    assert any("Invisible characters" in f for f in obf.flags)
    assert not any("Invisible characters" in f for f in plain.flags)


def test_nfkc_and_curly_quotes():
    r = analyze("ＵＲＧＥＮＴ: don’t wait, act now")  # full-width URGENT
    assert {"urgent", "don't wait", "act now"} <= set(r.vectors["urgency"].matched_keywords)


def test_emoji_zwj_is_not_flagged():
    r = analyze("Family photo \U0001F468‍\U0001F469‍\U0001F467 from the weekend")
    assert r.hidden_characters == 0 and r.flags == []


def test_false_intimacy_needs_two_cues():
    one = analyze("Please log in to your account to see the update.")
    assert one.vectors["familiarity"].score > 20
    assert not any("False intimacy" in f for f in one.flags)
    two = analyze("As discussed, please log in to your account to see the update.")
    assert any("False intimacy" in f for f in two.flags)


def test_short_keyword_list_floor():
    # base = min(matches / max(0.15 * list_size, 1) * 100, 90): the divisor never drops below 1
    from src import analyzer
    from src.taxonomy import MANIPULATION_VECTORS as V
    V["_tiny"] = {**V["curiosity"], "keywords": ["secret", "hidden"], "weight": 1.0}
    try:
        assert analyzer._score_vector("a secret", "_tiny").score == 90.0
    finally:
        del V["_tiny"]
