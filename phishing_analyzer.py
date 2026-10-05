import re
from urllib.parse import urlparse


# ==========================================================
# EMAIL PHISHING RISK ANALYZER
# ==========================================================

# Words related to urgency or pressure
URGENCY_WORDS = [
    "urgent",
    "immediately",
    "asap",
    "right now",
    "action required",
    "act now",
    "within 24 hours",
    "today",
    "final warning"
]


# Words related to account threats
ACCOUNT_THREATS = [
    "suspended",
    "disabled",
    "locked",
    "terminated",
    "restricted",
    "unauthorized access",
    "unusual activity",
    "security alert",
    "account compromised"
]


# Words asking for credentials or verification
CREDENTIAL_WORDS = [
    "password",
    "username",
    "login",
    "log in",
    "sign in",
    "verify",
    "verification",
    "authenticate",
    "confirm your account",
    "confirm your identity"
]


# Financial / reward language
FINANCIAL_WORDS = [
    "bank account",
    "payment",
    "credit card",
    "gift card",
    "wire transfer",
    "refund",
    "invoice",
    "prize",
    "winner",
    "you have won",
    "claim your reward"
]


# Language trying to make the user click something
CLICK_WORDS = [
    "click here",
    "click below",
    "follow this link",
    "open the link",
    "visit this link",
    "click the link",
    "download attachment"
]


# Known URL-shortening services
SHORTENED_URLS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly"
]


# ==========================================================
# HELPER FUNCTION
# ==========================================================

def find_matches(text, words):
    """
    Searches text for words/phrases from a list.

    Returns every phrase that was found.
    """

    text = text.lower()

    matches = []

    for word in words:

        if word in text:
            matches.append(word)

    return matches


# ==========================================================
# SENDER ANALYSIS
# ==========================================================

def analyze_sender(sender):

    score = 0
    findings = []

    sender = sender.strip().lower()


    # Basic email-address format
    email_pattern = (
        r'^[A-Za-z0-9._%+-]+@'
        r'[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'
    )


    # Check whether the sender looks like an email address
    if not re.match(email_pattern, sender):

        score += 25

        findings.append(
            "Invalid or unusual sender email format (+25)"
        )

        return score, findings


    # Separate username and domain
    username, domain = sender.split("@", 1)


    # Count numbers in username
    digit_count = sum(
        character.isdigit()
        for character in username
    )


    # Large numbers/random-looking usernames can be suspicious
    if digit_count >= 4:

        score += 8

        findings.append(
            "Sender username contains many numbers (+8)"
        )


    # Suspicious words inside sender domain
    suspicious_domain_words = [
        "verify",
        "verification",
        "security-alert",
        "account-security",
        "secure-login",
        "password",
        "support-team",
        "account-update"
    ]


    for word in suspicious_domain_words:

        if word in domain:

            score += 12

            findings.append(
                f"Suspicious sender domain contains '{word}' (+12)"
            )


    return score, findings


# ==========================================================
# SUBJECT ANALYSIS
# ==========================================================

def analyze_subject(subject):

    score = 0
    findings = []

    subject_lower = subject.lower()


    # Look for urgency
    urgency_matches = find_matches(
        subject_lower,
        URGENCY_WORDS
    )


    if urgency_matches:

        score += 12

        findings.append(
            "Subject contains urgency language: "
            + ", ".join(urgency_matches)
            + " (+12)"
        )


    # Look for account threats
    threat_matches = find_matches(
        subject_lower,
        ACCOUNT_THREATS
    )


    if threat_matches:

        score += 12

        findings.append(
            "Subject contains account/security threat language: "
            + ", ".join(threat_matches)
            + " (+12)"
        )


    # Look for credential-related language
    credential_matches = find_matches(
        subject_lower,
        CREDENTIAL_WORDS
    )


    if credential_matches:

        score += 10

        findings.append(
            "Subject requests account verification/login activity: "
            + ", ".join(credential_matches)
            + " (+10)"
        )


    # Lots of exclamation marks
    if subject.count("!") >= 2:

        score += 5

        findings.append(
            "Subject uses excessive exclamation marks (+5)"
        )


    # Detect excessive uppercase letters
    letters = [
        character
        for character in subject
        if character.isalpha()
    ]


    if len(letters) >= 5:

        uppercase_count = sum(
            character.isupper()
            for character in letters
        )

        uppercase_ratio = (
            uppercase_count / len(letters)
        )


        if uppercase_ratio >= 0.70:

            score += 5

            findings.append(
                "Subject uses excessive capital letters (+5)"
            )


    return score, findings


# ==========================================================
# BODY ANALYSIS
# ==========================================================

def analyze_body(body):

    score = 0
    findings = []

    body_lower = body.lower()


    # ------------------------------------------
    # URGENCY
    # ------------------------------------------

    urgency_matches = find_matches(
        body_lower,
        URGENCY_WORDS
    )


    if urgency_matches:

        score += 10

        findings.append(
            "Urgency/pressure language detected: "
            + ", ".join(urgency_matches)
            + " (+10)"
        )


    # ------------------------------------------
    # ACCOUNT THREATS
    # ------------------------------------------

    threat_matches = find_matches(
        body_lower,
        ACCOUNT_THREATS
    )


    if threat_matches:

        score += 15

        findings.append(
            "Account/security threat detected: "
            + ", ".join(threat_matches)
            + " (+15)"
        )


    # ------------------------------------------
    # CREDENTIAL REQUEST
    # ------------------------------------------

    credential_matches = find_matches(
        body_lower,
        CREDENTIAL_WORDS
    )


    if credential_matches:

        score += 15

        findings.append(
            "Credential/account language detected: "
            + ", ".join(credential_matches)
            + " (+15)"
        )


    # ------------------------------------------
    # CLICK REQUEST
    # ------------------------------------------

    click_matches = find_matches(
        body_lower,
        CLICK_WORDS
    )


    if click_matches:

        score += 15

        findings.append(
            "Message encourages clicking a link: "
            + ", ".join(click_matches)
            + " (+15)"
        )


    # ------------------------------------------
    # FINANCIAL LANGUAGE
    # ------------------------------------------

    financial_matches = find_matches(
        body_lower,
        FINANCIAL_WORDS
    )


    if financial_matches:

        score += 12

        findings.append(
            "Financial/reward language detected: "
            + ", ".join(financial_matches)
            + " (+12)"
        )


    return score, findings


# ==========================================================
# FIND URLS
# ==========================================================

def find_urls(text):

    # Finds http:// and https:// URLs
    pattern = r'https?://[^\s<>"]+'

    urls = re.findall(pattern, text)

    return urls


# ==========================================================
# URL ANALYSIS
# ==========================================================

def analyze_urls(urls):

    score = 0
    findings = []


    for url in urls:

        # Remove common punctuation that might appear
        # at the end of a sentence.
        clean_url = url.rstrip(".,);!?")

        parsed = urlparse(clean_url)

        domain = parsed.netloc.lower()


        # ------------------------------------------
        # HTTP
        # ------------------------------------------

        if clean_url.startswith("http://"):

            score += 10

            findings.append(
                f"Insecure HTTP link detected: {clean_url} (+10)"
            )


        # ------------------------------------------
        # SHORTENED URL
        # ------------------------------------------

        for shortener in SHORTENED_URLS:

            if (
                domain == shortener
                or domain.endswith("." + shortener)
            ):

                score += 20

                findings.append(
                    f"URL shortener detected: {domain} (+20)"
                )

                break


        # ------------------------------------------
        # IP ADDRESS
        # ------------------------------------------

        ip_pattern = (
            r'^(?:\d{1,3}\.){3}\d{1,3}'
            r'(?::\d+)?$'
        )


        if re.match(ip_pattern, domain):

            score += 25

            findings.append(
                f"URL uses an IP address instead of a normal domain: "
                f"{domain} (+25)"
            )


        # ------------------------------------------
        # SUSPICIOUS DOMAIN WORDS
        # ------------------------------------------

        suspicious_words = [
            "verify",
            "login",
            "signin",
            "password",
            "account",
            "security",
            "update"
        ]


        domain_matches = find_matches(
            domain,
            suspicious_words
        )


        if domain_matches:

            score += 10

            findings.append(
                f"Suspicious URL domain '{domain}' contains: "
                + ", ".join(domain_matches)
                + " (+10)"
            )


    return score, findings


# ==========================================================
# RISK LEVEL
# ==========================================================

def determine_risk(score):

    # 0 - 24
    if score < 25:
        return "LOW"

    # 25 - 49
    elif score < 50:
        return "MEDIUM"

    # 50+
    else:
        return "HIGH"


# ==========================================================
# COMPLETE ANALYSIS
# ==========================================================

def analyze_email(sender, subject, body):

    total_score = 0

    all_findings = []


    # Analyze sender
    sender_score, sender_findings = analyze_sender(sender)

    total_score += sender_score

    all_findings.extend(sender_findings)


    # Analyze subject
    subject_score, subject_findings = analyze_subject(subject)

    total_score += subject_score

    all_findings.extend(subject_findings)


    # Analyze body
    body_score, body_findings = analyze_body(body)

    total_score += body_score

    all_findings.extend(body_findings)


    # Find links in subject AND body
    urls = find_urls(subject + " " + body)


    # Analyze links
    url_score, url_findings = analyze_urls(urls)

    total_score += url_score

    all_findings.extend(url_findings)


    # Cap displayed score at 100
    displayed_score = min(total_score, 100)


    # Determine risk using the actual score
    risk = determine_risk(total_score)


    return (
        risk,
        displayed_score,
        urls,
        all_findings
    )


# ==========================================================
# PROGRAM
# ==========================================================

print("============================================")
print("        EMAIL PHISHING RISK ANALYZER")
print("============================================")


# Ask for sender
sender = input("\nSender Email: ")


# Ask for subject
subject = input("Subject: ")


# Allow the user to enter multiple lines for the body
print("\nPaste Email Body")
print("Type DONE on a new line when finished.\n")


body_lines = []


while True:

    line = input()

    if line.strip().upper() == "DONE":
        break

    body_lines.append(line)


# Combine all lines into one email body
body = "\n".join(body_lines)


# Run analysis
risk, score, urls, findings = analyze_email(
    sender,
    subject,
    body
)


# ==========================================================
# REPORT
# ==========================================================

print("\n============================================")
print("             SECURITY REPORT")
print("============================================")

print(f"Sender:     {sender}")
print(f"Subject:    {subject}")

print("--------------------------------------------")

print(f"Risk Level: {risk}")
print(f"Risk Score: {score}/100")
print(f"URLs Found: {len(urls)}")


# Show URLs
if urls:

    print("\nURLs Detected:")

    for url in urls:
        print(f"- {url}")


# Show findings
print("\nSecurity Indicators:")


if findings:

    for finding in findings:
        print(f"- {finding}")

else:

    print("- No common phishing indicators detected.")


# ==========================================================
# VERDICT
# ==========================================================

print("\n============================================")
print("                  VERDICT")
print("============================================")


if risk == "LOW":

    print("LOW RISK")

    print(
        "Few common phishing indicators were detected."
    )


elif risk == "MEDIUM":

    print("MEDIUM RISK")

    print(
        "Several suspicious characteristics were detected."
    )

    print(
        "Verify the sender and destination of links "
        "before interacting with the message."
    )


else:

    print("HIGH RISK")

    print(
        "Multiple strong phishing indicators were detected."
    )

    print(
        "Avoid clicking links or providing credentials "
        "until the message has been independently verified."
    )
