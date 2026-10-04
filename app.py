import ipaddress
import re
from urllib.parse import urlparse

from flask import Flask, render_template, request

app = Flask(__name__)

MAX_LENGTH = 2000

# Words that scammers like to use to build trust
SUSPICIOUS_WORDS = {
    "login", "signin", "verify", "verification", "secure", "security",
    "account", "accounts", "update", "confirm", "password", "banking",
    "wallet", "bonus", "free", "gift", "prize", "claim", "suspended",
    "unlock", "otp", "kyc", "billing", "refund",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy",
}

# Website endings that are often used for scams
RISKY_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "link", "work",
    "zip", "country", "icu", "rest", "buzz",
}

# Endings made of two parts, like co.in, so we find the real domain correctly
SECOND_LEVEL = {
    "co.in", "ac.in", "gov.in", "org.in", "net.in", "nic.in",
    "co.uk", "org.uk", "com.au", "co.jp", "com.br",
}

EXECUTABLE_ENDINGS = (".exe", ".scr", ".bat", ".msi", ".apk", ".jar")

# Brand name -> the real domains that brand uses
BRANDS = {
    "amazon": {"amazon.in", "amazon.com", "amazon.co.uk"},
    "paypal": {"paypal.com"},
    "google": {"google.com", "google.co.in"},
    "microsoft": {"microsoft.com"},
    "apple": {"apple.com"},
    "facebook": {"facebook.com"},
    "instagram": {"instagram.com"},
    "netflix": {"netflix.com"},
    "whatsapp": {"whatsapp.com"},
    "paytm": {"paytm.com"},
    "phonepe": {"phonepe.com"},
    "flipkart": {"flipkart.com"},
    "irctc": {"irctc.co.in"},
    "hdfc": {"hdfcbank.com"},
    "icici": {"icicibank.com"},
    "sbi": {"sbi.co.in", "onlinesbi.sbi"},
    "linkedin": {"linkedin.com"},
    "youtube": {"youtube.com"},
}

KNOWN_GOOD = set().union(*BRANDS.values())

# Numbers that scammers swap in for letters, like paypa1 or amaz0n
LOOKALIKE_TABLES = [
    str.maketrans("013457", "oleast"),
    str.maketrans("013457", "oieast"),
]


def is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def split_host(host):
    """Return (real domain, list of subdomains)."""
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in SECOND_LEVEL:
        keep = 3
    else:
        keep = 2
    return ".".join(labels[-keep:]), labels[:-keep]


def find_brand(tokens):
    for brand in BRANDS:
        if brand in tokens:
            return brand
    return None


def find_lookalike(tokens):
    for table in LOOKALIKE_TABLES:
        fixed = [t.translate(table) for t in tokens]
        for brand in BRANDS:
            if brand in fixed and brand not in tokens:
                return brand
    return None


def analyze(raw_url):
    """Read the text of a link and score how suspicious it looks.
    This function never opens the link."""
    if re.search(r"\s", raw_url):
        return None

    has_scheme = bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", raw_url))
    parsed = urlparse(raw_url if has_scheme else "http://" + raw_url)
    host = parsed.hostname or ""
    if not host:
        return None

    scheme = parsed.scheme.lower() if has_scheme else None
    ip_host = is_ip(host)
    if ip_host:
        registered, subdomains = host, []
    else:
        registered, subdomains = split_host(host)

    tokens = [t for t in re.split(r"[^a-z0-9]+", host) if t]
    path_text = (parsed.path + " " + parsed.query).lower()
    path_tokens = {t for t in re.split(r"[^a-z0-9]+", path_text) if t}
    known_good = registered in KNOWN_GOOD

    score = 0
    findings = []

    def add(points, level, title, detail):
        nonlocal score
        score += points
        findings.append({"level": level, "title": title, "detail": detail})

    if ip_host:
        add(30, "high", "IP address instead of a website name",
            "Real companies use a name like amazon.in. A raw IP address is a common sign of a fake or temporary site.")

    if "@" in parsed.netloc:
        add(25, "high", "Contains an @ symbol",
            f"Browsers ignore everything before the @. This link really goes to {host}, not to the name shown first.")

    if scheme == "http":
        add(15, "medium", "Not using HTTPS",
            "The connection is not encrypted. Real login pages almost always use HTTPS.")

    if len(raw_url) > 75:
        add(10, "low", "Long link",
            f"This link has {len(raw_url)} characters. Attackers hide the real destination inside long links.")

    if len(subdomains) >= 3:
        add(15, "medium", "Too many subdomains",
            f"The address has {len(subdomains)} parts in front of the real domain, which is {registered}. This is used to look like a trusted site.")

    if registered in SHORTENERS:
        add(20, "medium", "Shortened link",
            "Short links hide the real destination. Use a link-preview tool to expand it before opening.")

    tld = host.rsplit(".", 1)[-1]
    if not ip_host and tld in RISKY_TLDS:
        add(15, "medium", f"Risky ending (.{tld})",
            "This ending is cheap and often used for scam websites.")

    if not ip_host and not known_good:
        brand = find_brand(tokens)
        if brand:
            real = ", ".join(sorted(BRANDS[brand]))
            add(35, "high", f"Pretends to be {brand.title()}",
                f"The name '{brand}' appears in the address, but the real domain is {registered}. The genuine site uses {real}.")
        else:
            fake = find_lookalike(tokens)
            if fake:
                add(35, "high", f"Look-alike spelling of {fake.title()}",
                    f"The address swaps letters for numbers to imitate '{fake}'. The real domain here is {registered}.")

    if any(label.startswith("xn--") for label in host.split(".")):
        add(20, "high", "Look-alike characters (punycode)",
            "The address uses special characters that can look like normal letters, such as a Cyrillic 'a' that looks like an English 'a'.")

    if not ip_host and host.count("-") >= 2:
        add(8, "low", "Many hyphens in the domain",
            "Scam domains often chain words together, like secure-login-update.com.")

    if not known_good:
        host_words = sorted(set(tokens) & SUSPICIOUS_WORDS)
        if host_words:
            add(min(20, 10 * len(host_words)), "medium", "Suspicious words in the domain",
                "Words like " + ", ".join(host_words) + " are often used to build trust in fake sites.")

    path_words = sorted(path_tokens & SUSPICIOUS_WORDS)
    if path_words:
        add(min(8, 4 * len(path_words)), "low", "Suspicious words in the link path",
            "The link contains " + ", ".join(path_words) + ". Real sites use these words too, so check the domain carefully.")

    try:
        port = parsed.port
    except ValueError:
        port = None
    if port not in (None, 80, 443):
        add(10, "medium", "Unusual port number",
            f"The link uses port {port}. Normal websites rarely do.")

    if re.search(r"https?(://|%3a%2f%2f)", path_text):
        add(10, "medium", "Contains another link",
            "A link hidden inside a link is often used to redirect you to a fake site.")

    if parsed.path.lower().endswith(EXECUTABLE_ENDINGS):
        add(20, "high", "Links to a downloadable program",
            "Files like .exe or .apk can install malware. Real login pages are not downloads.")

    score = min(score, 100)
    order = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: order[f["level"]])

    if score >= 45:
        risk, icon = "High", "🔴"
        advice = "Do not open this link or enter any details. If it came in a message, delete it or report it."
    elif score >= 20:
        risk, icon = "Medium", "🟠"
        advice = "Be careful. Do not enter passwords or OTPs. Go to the official website yourself instead."
    else:
        risk, icon = "Low", "🟢"
        advice = "No strong warning signs found, but no checker is perfect. Never share OTPs, and open the official site yourself for money or logins."

    return {
        "url": raw_url,
        "registered": registered,
        "score": score,
        "risk": risk,
        "icon": icon,
        "advice": advice,
        "findings": findings,
    }


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    error = None
    url = ""

    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if not url:
            error = "Please paste a link first."
        elif len(url) > MAX_LENGTH:
            error = "That link is too long to check."
        else:
            try:
                result = analyze(url)
            except ValueError:
                result = None
            if result is None:
                error = "That does not look like a valid link. Make sure it has no spaces."

    return render_template("index.html", result=result, error=error, url=url)


if __name__ == "__main__":
    app.run(debug=True, port=5003)