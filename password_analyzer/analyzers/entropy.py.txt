import math
from dataclasses import dataclass

@dataclass
class EntropyResult:
    bits: float
    charset_size: int
    crack_time: str

def _estimate_charset_size(password: str) -> int:
    size = 0

    if any(c.islower() for c in password):
        size += 26

    if any(c.isupper() for c in password):
        size += 26

    if any(c.isdigit() for c in password):
        size += 10

    if any(not c.isalnum() for c in password):
        size += 32

    return max(size, 1)

def _shannon_entropy(password: str) -> float:
    if not password:
        return 0.0

    freq = {}

    for ch in password:
        freq[ch] = freq.get(ch, 0) + 1

    length = len(password)

    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )

def _crack_time_label(bits: float) -> str:
    guesses = 2 ** bits
    seconds = guesses / 10_000_000_000

    thresholds = [
        (60, "less than a minute"),
        (3600, "a few minutes"),
        (86400, "a few hours"),
        (2592000, "a few days"),
        (31536000, "a few months"),
        (3153600000, "centuries"),
    ]

    for limit, label in thresholds:
        if seconds < limit:
            return label

    return "millions of years"

def analyze_entropy(password: str) -> EntropyResult:
    charset_size = _estimate_charset_size(password)

    bits = _shannon_entropy(password) * len(password)

    crack_time = _crack_time_label(bits)

    return EntropyResult(
        bits=round(bits, 1),
        charset_size=charset_size,
        crack_time=crack_time
    )