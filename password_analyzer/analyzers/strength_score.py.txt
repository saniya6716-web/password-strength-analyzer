from app.analyzers.entropy import EntropyResult
from app.analyzers.charset import CharsetResult
from app.analyzers.patterns import PatternMatch

SEVERITY_PENALTY = {
    "low": 5,
    "medium": 10,
    "high": 15
}

LABELS = [
    (20, "Very Weak"),
    (40, "Weak"),
    (60, "Fair"),
    (80, "Strong"),
    (101, "Very Strong")
]

def _entropy_score(bits: float) -> int:
    return min(60, int(bits / 1.2))

def _charset_bonus(result: CharsetResult) -> int:
    present = sum(
        1 for v in result.composition.values()
        if v["count"] > 0
    )

    return present * 5

def _pattern_penalty(patterns: list[PatternMatch]) -> int:
    return sum(
        SEVERITY_PENALTY.get(p.severity, 5)
        for p in patterns
    )

def _score_to_label(score: int) -> str:
    for threshold, label in LABELS:
        if score < threshold:
            return label

    return "Very Strong"

def compute_score(entropy, charset, patterns) -> tuple[int, str]:
    score = _entropy_score(entropy.bits)

    score += _charset_bonus(charset)

    score -= _pattern_penalty(patterns)

    score = max(0, min(100, score))

    return score, _score_to_label(score)