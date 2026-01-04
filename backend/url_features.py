# backend/url_features.py
import re
import tldextract
import whois
import requests
from datetime import datetime
from bs4 import BeautifulSoup
import socket

# NOTE: keep this file simple and deterministic; heavy network calls are tried but safely handled.

def safe_whois_age(domain):
    try:
        data = whois.whois(domain)
        creation_date = data.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            return datetime.now().year - creation_date.year
    except Exception:
        pass
    return 0

def extract_url_features(url):
    """
    Returns:
      - features: list of numeric features (length = 87)
      - signals: dict with boolean/int signals for explanations
    """
    features = []
    signals = {}

    # canonicalize
    url = url.strip()

    # --- Basic numeric features (small set; pad later to 87) ---
    features.append(len(url))  # url length

    # hostname length
    try:
        hostname = tldextract.extract(url).fqdn or ""
    except Exception:
        hostname = ""
    features.append(len(hostname))

    # contains IP
    has_ip = bool(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", url))
    features.append(1 if has_ip else 0)
    signals["contains_ip"] = has_ip

    # number of dots
    nb_dots = url.count(".")
    features.append(nb_dots)
    signals["nb_dots"] = nb_dots

    # hyphens
    nb_hyphens = url.count("-")
    features.append(nb_hyphens)
    signals["nb_hyphens"] = nb_hyphens

    # @ symbol
    has_at = "@" in url
    features.append(1 if has_at else 0)
    signals["has_at_symbol"] = has_at

    # protocol is https?
    uses_https = url.lower().startswith("https")
    features.append(1 if uses_https else 0)
    signals["uses_https"] = uses_https

    # digit ratio
    digit_ratio = sum(c.isdigit() for c in url) / (len(url) if len(url) > 0 else 1)
    features.append(digit_ratio)
    signals["digit_ratio"] = digit_ratio

    # shortener check (common)
    shorteners = ["bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly"]
    is_shortener = any(s in url for s in shorteners)
    features.append(1 if is_shortener else 0)
    signals["is_shortener"] = is_shortener

    # domain age via WHOIS
    try:
        domain = tldextract.extract(url).registered_domain
    except Exception:
        domain = ""
    domain_age = safe_whois_age(domain) if domain else 0
    features.append(domain_age)
    signals["domain_age"] = domain_age

    # basic suspicious words in path
    suspicious_words = ["login", "verify", "secure", "account", "update", "bank", "confirm", "signin", "reset"]
    path_lower = url.lower()
    s_count = sum(1 for w in suspicious_words if w in path_lower)
    features.append(s_count)
    signals["suspicious_word_count"] = s_count

    # presence of "@" in path (already captured), presence of suspicious TLD (like .tk)
    suspicious_tlds = [".tk", ".pw", ".ml", ".gq"]
    has_susp_tld = any(t in url.lower() for t in suspicious_tlds)
    features.append(1 if has_susp_tld else 0)
    signals["suspicious_tld"] = has_susp_tld

    # trailing slash count, path length
    path_len = len(url.split("/", 3)[-1]) if "/" in url else 0
    features.append(path_len)
    signals["path_length"] = path_len

    # very long domain (subdomain squatting)
    nb_subdomains = hostname.count(".") if hostname else 0
    features.append(nb_subdomains)
    signals["nb_subdomains"] = nb_subdomains

    # common phishing heuristic: many query params
    nb_qm = url.count("?")
    features.append(nb_qm)
    signals["nb_query_mark"] = nb_qm

    # check HTTP in path token (like http://example.com/<http>)
    features.append(1 if "http" in url.split("://")[-1] else 0)

    # placeholder extra simple features to reach small count before padding
    # (we will pad/trim to 87 later)
    # add a few zeros for intermediate features
    for i in range(20):
        features.append(0)

    # --- Now a few content-based signals (best-effort, safe) ---
    page_title_empty = False
    try:
        resp = requests.get(url, timeout=3, allow_redirects=True, headers={"User-Agent": "Mozilla/5.0"})
        html = resp.text[:200000]  # avoid huge pages
        soup = BeautifulSoup(html, "html.parser")
        title = soup.title.string.strip() if soup.title and soup.title.string else ""
        if not title:
            page_title_empty = True
    except Exception:
        # network failures are common; treat as unknown
        page_title_empty = False

    features.append(1 if page_title_empty else 0)
    signals["empty_title"] = page_title_empty

    # quick server reachability check (DNS)
    dns_ok = False
    try:
        if domain:
            socket.gethostbyname(domain)
            dns_ok = True
    except Exception:
        dns_ok = False
    features.append(1 if not dns_ok else 0)  # 1 if dns lookup failed -> suspicious
    signals["dns_lookup_failed"] = not dns_ok

    # --- Final step: force EXACTLY 87 numeric features ---
    REQUIRED_FEATURES = 87
    if len(features) < REQUIRED_FEATURES:
        features += [0] * (REQUIRED_FEATURES - len(features))
    else:
        features = features[:REQUIRED_FEATURES]

    return features, signals
