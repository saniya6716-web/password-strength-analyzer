import hashlib
from dataclasses import dataclass
import requests

HIBP_URL = "https://api.pwnedpasswords.com/range/{}"

@dataclass
class BreachResult:
    breached: bool | None
    count: int
    error: str | None

def _sha1_prefix_suffix(password: str) -> tuple[str, str]:
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()

    return digest[:5], digest[5:]

def _query_hibp(prefix: str, timeout: int, user_agent: str) -> str:
    response = requests.get(
        HIBP_URL.format(prefix),
        timeout=timeout,
        headers={"User-Agent": user_agent}
    )

    response.raise_for_status()

    return response.text

def _find_suffix_in_response(suffix: str, response_text: str) -> int:
    for line in response_text.splitlines():
        parts = line.split(":")

        if len(parts) == 2 and parts[0] == suffix:
            return int(parts[1])

    return 0

def check_breach(password: str, timeout: int, user_agent: str) -> BreachResult:
    try:
        prefix, suffix = _sha1_prefix_suffix(password)

        response_text = _query_hibp(prefix, timeout, user_agent)

        count = _find_suffix_in_response(suffix, response_text)

        return BreachResult(
            breached=count > 0,
            count=count,
            error=None
        )

    except requests.Timeout:
        return BreachResult(
            breached=None,
            count=0,
            error="Breach check timed out."
        )

    except requests.RequestException as e:
        return BreachResult(
            breached=None,
            count=0,
            error=f"Breach check unavailable: {e}"
        )