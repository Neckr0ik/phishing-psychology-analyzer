"""
Manipulation Vector Taxonomy
Maps social engineering tactics to the cognitive biases they exploit.

Theoretical grounding:
- Cialdini, R. B. (1984). Influence: The Psychology of Persuasion.
- Kahneman, D. (2011). Thinking, Fast and Slow.
- Loewenstein, G. (1994). The Psychology of Curiosity (Information Gap Theory).
- MITRE ATT&CK Framework (enterprise.attack.mitre.org) for tactic classification.
"""

MANIPULATION_VECTORS = {
    "urgency": {
        "label": "Urgency / Time Pressure",
        "bias": "Loss Aversion + Availability Heuristic",
        "mechanism": "Artificially compressed time horizons prevent System 2 (deliberate) reasoning, "
                     "forcing reactive System 1 responses based on perceived loss.",
        "mitre_ref": "T1566 - Phishing; Social Engineering via Temporal Pressure",
        "keywords": [
            "urgent", "immediately", "right now", "act now", "expires", "expiring",
            "deadline", "limited time", "hours left", "minutes left", "today only",
            "last chance", "don't wait", "must respond", "respond immediately",
            "time sensitive", "time-sensitive", "asap", "as soon as possible",
            "no time", "running out of time", "24 hours", "48 hours", "within hours",
        ],
        "weight": 1.5,
        "color": "#E74C3C",
        "risk_boost": 0.2,
    },
    "authority": {
        "label": "Authority / Impersonation",
        "bias": "Authority Bias + Halo Effect",
        "mechanism": "Invokes legitimate institutional trust cues, transferring credibility "
                     "to the malicious actor and suppressing skeptical evaluation.",
        "mitre_ref": "T1585 - Establish Accounts; T1656 - Impersonation",
        "keywords": [
            "official", "verified", "authorized", "certified", "compliance",
            "ceo", "chief executive", "director", "president", "it department",
            "security team", "hr department", "management", "administrator", "admin",
            "legal department", "government", "federal", "irs", "ssa", "treasury",
            "microsoft", "apple", "google", "paypal", "amazon", "bank",
            "helpdesk", "tech support", "system administrator", "your provider",
        ],
        "weight": 1.4,
        "color": "#E67E22",
        "risk_boost": 0.15,
    },
    "fear_threat": {
        "label": "Fear / Threat Appraisal",
        "bias": "Negativity Bias + Loss Aversion + Threat Appraisal",
        "mechanism": "Activates the amygdala-driven threat response, elevating cortisol and "
                     "narrowing attention to the perceived threat while reducing analytical processing.",
        "mitre_ref": "T1566 - Phishing; Social Engineering via Fear Arousal",
        "keywords": [
            "suspended", "compromised", "hacked", "breach", "breach detected",
            "virus", "malware", "ransomware", "unauthorized", "unauthorized access",
            "blocked", "terminated", "disabled", "deleted", "penalty", "fine",
            "lawsuit", "legal action", "criminal", "consequences", "warning",
            "alert", "critical", "severe", "account locked", "account disabled",
            "unusual activity", "suspicious activity", "verify immediately",
            "failure to comply", "will result in", "irrecoverable",
        ],
        "weight": 1.8,
        "color": "#C0392B",
        "risk_boost": 0.3,
    },
    "scarcity": {
        "label": "Scarcity / Exclusivity",
        "bias": "Scarcity Heuristic + FOMO",
        "mechanism": "Perceived scarcity elevates subjective value (Brock, 1968) and "
                     "triggers fear of missing out, accelerating commitment decisions.",
        "mitre_ref": "T1566 - Social Engineering via Artificial Scarcity",
        "keywords": [
            "limited", "exclusive", "only a few", "selected", "special offer",
            "one-time", "running out", "few remaining", "rare opportunity",
            "unique", "not available to everyone", "invite only", "vip",
            "premium access", "privileged", "chosen", "handpicked",
            "special access", "cannot be extended", "no exceptions",
        ],
        "weight": 1.1,
        "color": "#8E44AD",
        "risk_boost": 0.1,
    },
    "reciprocity": {
        "label": "Reciprocity / Reward Baiting",
        "bias": "Reciprocity Norm + Variable Reward",
        "mechanism": "Unsolicited gifts activate the reciprocity norm (Cialdini, 1984), "
                     "creating social obligation. Variable reward schedules produce dopaminergic "
                     "engagement similar to gambling mechanisms.",
        "mitre_ref": "T1566 - Phishing (Baiting); Social Engineering via Reward",
        "keywords": [
            "free", "gift", "reward", "prize", "won", "winner", "congratulations",
            "selected as", "bonus", "credit", "refund", "cashback", "claim",
            "collect", "redeem", "voucher", "coupon", "you qualify",
            "eligible for", "special reward", "no cost", "zero cost",
            "at no charge", "complimentary",
        ],
        "weight": 1.2,
        "color": "#27AE60",
        "risk_boost": 0.1,
    },
    "social_proof": {
        "label": "Social Proof / Consensus",
        "bias": "Social Proof + Bandwagon Effect",
        "mechanism": "Uncertainty about correct behavior leads individuals to assume "
                     "that others' actions reflect superior knowledge (Sherif, 1936), "
                     "normalizing compliance with the request.",
        "mitre_ref": "T1566 - Social Engineering via Consensus Manufacturing",
        "keywords": [
            "everyone", "thousands", "millions", "most people", "join",
            "community", "trusted by", "popular", "trending", "your peers",
            "your colleagues", "industry standard", "widely used",
            "most companies", "professionals agree", "experts recommend",
            "people like you", "your network",
        ],
        "weight": 0.9,
        "color": "#2980B9",
        "risk_boost": 0.05,
    },
    "familiarity": {
        "label": "Familiarity / False Intimacy",
        "bias": "Mere Exposure Effect + In-group Bias",
        "mechanism": "Contextual details that mirror the target's environment create "
                     "a false sense of pre-existing relationship, reducing default "
                     "skepticism toward unknown communicators.",
        "mitre_ref": "T1585.001 - Social Media Accounts; Pretexting",
        "keywords": [
            "your account", "your information", "as discussed", "following up",
            "as we agreed", "your team", "your organization", "your bank",
            "your subscription", "your order", "your profile", "your data",
            "our records show", "we noticed", "we detected", "per our conversation",
            "as per your request", "you recently", "we see that you",
        ],
        "weight": 1.0,
        "color": "#16A085",
        "risk_boost": 0.1,
    },
    "curiosity": {
        "label": "Curiosity / Information Gap",
        "bias": "Curiosity Gap + Zeigarnik Effect",
        "mechanism": "Loewenstein's (1994) information-gap theory posits that partial "
                     "information creates aversive arousal compelling gap-closure behavior, "
                     "overriding caution in the drive to resolve uncertainty.",
        "mitre_ref": "T1566 - Phishing (Clickbait); Social Engineering via Curiosity",
        "keywords": [
            "you won't believe", "secret", "revealed", "discover", "click to see",
            "find out", "what they don't want you to know", "exclusive access",
            "hidden", "confidential", "restricted", "leaked", "the truth about",
            "shocking", "surprising", "you need to see this", "open to find out",
            "can't be shared publicly", "eyes only", "for your eyes",
        ],
        "weight": 1.0,
        "color": "#F39C12",
        "risk_boost": 0.1,
    },
}

RISK_LEVELS = {
    "LOW":      {"range": (0, 25),   "color": "#27AE60", "label": "Low Risk",      "icon": "LOW"},
    "MEDIUM":   {"range": (25, 50),  "color": "#F39C12", "label": "Medium Risk",   "icon": "MED"},
    "HIGH":     {"range": (50, 75),  "color": "#E67E22", "label": "High Risk",     "icon": "HIGH"},
    "CRITICAL": {"range": (75, 101), "color": "#C0392B", "label": "Critical Risk", "icon": "CRIT"},
}


def get_risk_level(composite_score: float) -> dict:
    for level_id, level_data in RISK_LEVELS.items():
        lo, hi = level_data["range"]
        if lo <= composite_score < hi:
            return {**level_data, "id": level_id}
    return {**RISK_LEVELS["CRITICAL"], "id": "CRITICAL"}
