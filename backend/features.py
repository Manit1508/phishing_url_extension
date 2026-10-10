import re
import math
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".buzz", ".work", ".fit", ".tk", ".ml", ".ga", 
    ".cf", ".gq", ".click", ".link", ".surf", ".rest", ".club"
}

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "bank", "account", "update", 
    "signin", "wallet", "confirm", "auth", "credential", "recover"
]

def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())

def extract_url_features(url: str) -> dict:
    url_lower = url.lower().strip()
    
    # Normalize short-form URLs (e.g., 'apple.com' -> 'https://apple.com')
    if not url_lower.startswith(("http://", "https://")):
        url_lower = "https://" + url_lower
        
    parsed = urlparse(url_lower)
    hostname = parsed.hostname or ""
    path = parsed.path or ""

    # Length metrics
    url_len = len(url_lower)
    hostname_len = len(hostname)
    path_len = len(path)

    # Character counts
    num_digits = sum(c.isdigit() for c in url_lower)
    digit_ratio = (num_digits / url_len) if url_len > 0 else 0.0
    num_dots = url_lower.count(".")
    num_hyphens = hostname.count("-")
    num_slashes = url_lower.count("/")
    num_subdomains = max(0, len(hostname.split(".")) - 2) if hostname else 0

    # Structural red flags
    has_ip = 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname) else 0
    num_at = 1 if "@" in url_lower else 0
    is_https = 1 if parsed.scheme == "https" else 0
    has_suspicious_tld = 1 if any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS) else 0
    has_keyword = 1 if any(kw in url_lower for kw in SUSPICIOUS_KEYWORDS) else 0
    entropy = calculate_entropy(hostname)

    return {
        "url_length": url_len,
        "hostname_length": hostname_len,
        "path_length": path_len,
        "num_digits": num_digits,
        "digit_ratio": round(digit_ratio, 4),
        "num_dots": num_dots,
        "num_hyphens": num_hyphens,
        "num_slashes": num_slashes,
        "num_subdomains": num_subdomains,
        "has_ip": has_ip,
        "num_at": num_at,
        "is_https": is_https,
        "has_suspicious_tld": has_suspicious_tld,
        "has_suspicious_keyword": has_keyword,
        "entropy": round(entropy, 4)
    }