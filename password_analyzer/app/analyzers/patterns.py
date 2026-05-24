import re
from typing import NamedTuple

KEYBOARD_WALKS = [
    "qwerty", "qwert", "werty",
    "asdfg", "asdf",
    "zxcvb", "zxcv",
    "12345", "23456", "34567",
    "45678", "56789", "67890",
    "abcde", "abcdef", "zyxwv"
]

TOP_PASSWORDS = [
    "password", "passw0rd", "password1",
    "letmein", "iloveyou", "monkey",
    "dragon", "master", "sunshine",
    "princess", "welcome", "shadow",
    "superman", "michael", "football",
    "baseball", "liverpool", "chelsea",
    "arsenal", "batman", "admin",
    "login", "solo", "starwars",
    "hello", "trustno1", "hunter",
    "mustang", "access", "flower"
]

LEET_MAP = str.maketrans("@3!1045$7", "aeiiOasst")

class PatternMatch(NamedTuple):
    type: str
    description: str
    severity: str

def detect_keyboard_walks(password: str) -> list[PatternMatch]:
    lower = password.lower()

    for walk in KEYBOARD_WALKS:
        if walk in lower:
            return [
                PatternMatch(
                    "keyboard_walk",
                    f'Keyboard sequence "{walk}" found',
                    "medium"
                )
            ]

    return []

def detect_repeated_chars(password: str) -> list[PatternMatch]:
    match = re.search(r"(.)\1{2,}", password)

    if match:
        return [
            PatternMatch(
                "repeated_chars",
                f'Repeated character "{match.group(1)}" found',
                "medium"
            )
        ]

    return []

def detect_date_patterns(password: str) -> list[PatternMatch]:
    patterns = [
        (r"\b(19|20)\d{2}\b", "Year pattern detected"),
        (r"\b(0[1-9]|1[0-2])[\/\-](0[1-9]|[12]\d|3[01])\b", "Date pattern"),
        (r"(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)\d*", "Month name detected"),
    ]

    for pattern, desc in patterns:
        if re.search(pattern, password, re.IGNORECASE):
            return [
                PatternMatch(
                    "date_pattern",
                    desc,
                    "low"
                )
            ]

    return []

def detect_common_words(password: str) -> list[PatternMatch]:
    lower = password.lower()

    for word in TOP_PASSWORDS:
        if word in lower:
            return [
                PatternMatch(
                    "common_word",
                    f'Common password word "{word}" found',
                    "high"
                )
            ]

    return []

def detect_leet_substitutions(password: str) -> list[PatternMatch]:
    normalized = password.lower().translate(LEET_MAP)

    for word in TOP_PASSWORDS:
        if word in normalized and word not in password.lower():
            return [
                PatternMatch(
                    "leet_speak",
                    f'Leet substitution of "{word}" detected',
                    "medium"
                )
            ]

    return []

ALL_DETECTORS = [
    detect_keyboard_walks,
    detect_repeated_chars,
    detect_date_patterns,
    detect_common_words,
    detect_leet_substitutions,
]

def detect_all_patterns(password: str) -> list[PatternMatch]:
    results = []

    for detector in ALL_DETECTORS:
        results.extend(detector(password))

    return results