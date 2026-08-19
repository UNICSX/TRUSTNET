from urllib.parse import urlparse
import re
from difflib import SequenceMatcher

KNOWN_BRANDS = [
    "paypal",
    "microsoft",
    "google",
    "amazon",
    "apple",
    "github",
    "netflix",
    "slack",
    "notion",
]

SUSPICIOUS_TLDS = [
    ".ru",
    ".xyz",
    ".info",
    ".top",
    ".click",
]

SOCIAL_ENGINEERING_KEYWORDS = [
    "urgent",
    "verify your account",
    "immediately",
    "password",
    "gift card",
    "click here",
    "limited",
    "security alert",
    "suspended",
]

def check_url_reputation(url):
    findings = []

    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    # Check for IP address
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
        findings.append("URL uses an IP address instead of a domain.")

    # Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            findings.append(f"Suspicious top-level domain: {tld}")

    # Executable downloads
    if parsed.path.endswith(".exe"):
        findings.append("URL points to an executable file.")

    # Typosquatting detection
    cleaned = domain.replace("-", "").replace(".", "")

    for brand in KNOWN_BRANDS:
        similarity = SequenceMatcher(None, cleaned, brand).ratio()

        if similarity > 0.75 and brand not in cleaned:
            findings.append(f"Possible typosquatting of '{brand}'.")

    return {
        "url": url,
        "safe": len(findings) == 0,
        "findings": findings,
    }


def extract_email_metadata(sender, reply_to, subject, body):
    findings = []

    sender_domain = sender.split("@")[-1].lower()
    reply_domain = reply_to.split("@")[-1].lower()

    # Sender and Reply-To mismatch
    if sender_domain != reply_domain:
        findings.append("Sender and Reply-To domains do not match.")

    # Social engineering keywords
    email_text = (subject + " " + body).lower()

    for keyword in SOCIAL_ENGINEERING_KEYWORDS:
        if keyword in email_text:
            findings.append(f"Contains suspicious phrase: '{keyword}'")

    # Brand impersonation in sender domain
    cleaned = sender_domain.replace("-", "").replace(".", "")

    for brand in KNOWN_BRANDS:
        similarity = SequenceMatcher(None, cleaned, brand).ratio()

        if similarity > 0.75 and brand not in cleaned:
            findings.append(f"Possible impersonation of '{brand}'.")

    return {
        "sender_domain": sender_domain,
        "reply_to_domain": reply_domain,
        "safe": len(findings) == 0,
        "findings": findings,
    }
# Convert Sequence matcher step to normalizing common lookalike characters.


def check_sender_domain_age(domain):
    """
    Mocked domain age estimation.
    In production this would query a WHOIS/RDAP API.
    """

    domain = domain.lower()

    findings = []

    suspicious = False

    # Hyphens often appear in fake domains
    if "-" in domain:
        findings.append("Domain contains hyphens.")
        suspicious = True

    # Numbers inside domain
    if any(char.isdigit() for char in domain):
        findings.append("Domain contains numeric characters.")
        suspicious = True

    # Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            findings.append(f"Uses suspicious TLD ({tld})")
            suspicious = True

    estimated_age = "new (< 6 months)" if suspicious else "established"

    return {
        "domain": domain,
        "estimated_age": estimated_age,
        "suspicious": suspicious,
        "findings": findings,
        "note": "Mocked heuristic. Replace with WHOIS/RDAP lookup in production."
    }


def flag_for_review(email_id, reason):
    print(f"\n[ACTION] Email {email_id} flagged for human review.")
    print(f"Reason: {reason}")

    return {
        "status": "flagged",
        "email_id": email_id,
        "reason": reason
    }