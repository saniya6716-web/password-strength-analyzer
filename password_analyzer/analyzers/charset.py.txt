from dataclasses import dataclass

@dataclass
class CharsetResult:
    composition: dict
    missing_classes: list[str]

def analyze_charset(password: str) -> CharsetResult:
    length = len(password) or 1

    classes = {
        "lowercase": sum(1 for c in password if c.islower()),
        "uppercase": sum(1 for c in password if c.isupper()),
        "digits": sum(1 for c in password if c.isdigit()),
        "symbols": sum(1 for c in password if not c.isalnum()),
    }

    composition = {
        label: {
            "count": count,
            "percent": round(count / length * 100, 1)
        }
        for label, count in classes.items()
    }

    missing = [
        label for label, count in classes.items()
        if count == 0
    ]

    return CharsetResult(
        composition=composition,
        missing_classes=missing
    )