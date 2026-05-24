from dataclasses import dataclass, asdict

@dataclass
class PasswordReport:
    score: int
    label: str
    entropy: float
    charset_size: int
    crack_time: str
    charset_composition: dict
    patterns: list[dict]
    breached: bool | None
    breach_count: int
    advice: list[str]
    error: str | None

    def to_dict(self) -> dict:
        return asdict(self)

def build_advice(entropy, charset, patterns, breach) -> list[str]:
    tips = []

    if breach.breached:
        tips.append(
            "This password was found in data breaches — stop using it immediately."
        )

    if entropy.bits < 40:
        tips.append(
            "Use a longer password (12+ characters) to dramatically increase strength."
        )

    for cls in charset.missing_classes:
        tips.append(
            f"Add {cls} characters to increase your character pool."
        )

    severity_map = {p.type: p for p in patterns}

    if "keyboard_walk" in severity_map:
        tips.append(
            "Avoid keyboard sequences like 'qwerty' or '12345'."
        )

    if "repeated_chars" in severity_map:
        tips.append(
            "Don't repeat the same character multiple times in a row."
        )

    if "date_pattern" in severity_map:
        tips.append(
            "Avoid using dates or years — they're easy to guess."
        )

    if "common_word" in severity_map:
        tips.append(
            "Remove common password words; use a passphrase instead."
        )

    if "leet_speak" in severity_map:
        tips.append(
            "Leet substitutions (like p@ssw0rd) are well-known and easily cracked."
        )

    if not tips:
        tips.append(
            "Great password! Consider using a password manager to store it safely."
        )

    return tips