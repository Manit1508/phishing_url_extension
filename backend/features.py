import re
import math
from urllib.parse import urlparse

def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())

def extract_url_features(url: str) -> dict:
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    
    # Extract structural features from the URL string
    url_length = len(url)
    has_ip = 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname) else 0
    num_dots = url.count(".")
    num_hyphens = url.count("-")
    num_at = url.count("@")
    num_subdomains = max(0, len(hostname.split(".")) - 2) if hostname else 0
    entropy = calculate_entropy(url)

    # Check for keywords often used to trick users
    keywords = ["login", "verify", "secure", "bank", "account", "update", "signin"]
    has_suspicious_keyword = 1 if any(kw in url.lower() for kw in keywords) else 0

    return {
        "url_length": url_length,
        "has_ip": has_ip,
        "num_dots": num_dots,
        "num_hyphens": num_hyphens,
        "num_at": num_at,
        "num_subdomains": num_subdomains,
        "entropy": entropy,
        "has_suspicious_keyword": has_suspicious_keyword
    }