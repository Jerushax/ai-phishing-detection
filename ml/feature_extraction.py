import re
import tldextract
import whois
from datetime import datetime

def extract_features(url):
    features = []

    # 1. URL Length
    features.append(len(url))

    # 2. Number of dots
    features.append(url.count('.'))

    # 3. Contains IP address
    features.append(1 if re.search(r"\d+\.\d+\.\d+\.\d+", url) else 0)

    # 4. Uses HTTPS
    features.append(1 if url.startswith("https") else 0)

    # 5. Suspicious words
    suspicious_words = ["login", "verify", "secure", "account", "update", "bank"]
    features.append(sum(word in url.lower() for word in suspicious_words))

    # 6. Domain age
    try:
        domain = tldextract.extract(url).registered_domain
        data = whois.whois(domain)
        creation_date = data.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        age = datetime.now().year - creation_date.year
    except:
        age = 0

    features.append(age)

    return features
