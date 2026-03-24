from flask import Flask, render_template, request
import os
import pickle
import requests
import socket
import ssl
import dns.resolver
import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from datetime import datetime
import pandas as pd

app = Flask(__name__)

# ---------------- LOAD MODEL ----------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(BASE_DIR, "model.pkl")

with open(model_path, "rb") as f:
    model = pickle.load(f)

# ---------------- CONFIG ----------------

SUSPICIOUS_KEYWORDS = [
    "verify-account",
    "update-account",
    "confirm-password",
    "security-alert",
    "free-money",
    "claim-reward",
    "urgent-action",
    "limited-offer"
]

# ---------------- UTILITIES ----------------

def extract_domain(url):

    if not url.startswith("http"):
        url = "http://" + url

    parsed = urlparse(url)

    domain = parsed.netloc.lower()

    if domain.startswith("www."):
        domain = domain[4:]

    return domain


def https_used(url):
    return url.startswith("https")


def digit_count(url):
    return sum(c.isdigit() for c in url)


def suspicious_keywords(url):

    found = []

    for word in SUSPICIOUS_KEYWORDS:
        if word in url.lower():
            found.append(word)

    return found


# ---------------- DOMAIN AGE (RDAP) ----------------

def get_domain_age(domain):

    rdap_servers = [
        "https://rdap.org/domain/",
        "https://rdap.verisign.com/com/v1/domain/",
        "https://rdap.publicinterestregistry.org/rdap/domain/"
    ]

    for server in rdap_servers:

        try:

            response = requests.get(server + domain, timeout=5)

            if response.status_code != 200:
                continue

            data = response.json()

            events = data.get("events", [])

            for event in events:

                if event.get("eventAction") == "registration":

                    creation_date = event.get("eventDate")

                    creation_date = datetime.fromisoformat(
                        creation_date.replace("Z", "")
                    )

                    today = datetime.utcnow()

                    diff = today - creation_date

                    days = diff.days
                    years = days // 365
                    months = days // 30

                    if years > 0:
                        return f"{years} years"

                    elif months > 0:
                        return f"{months} months"

                    else:
                        return f"{days} days"

        except:
            continue

    return "Not Available"


# ---------------- DNS CHECK ----------------

def check_dns(domain):

    try:
        dns.resolver.resolve(domain, 'A')
        return True
    except:
        return False


# ---------------- MX RECORD CHECK ----------------

def check_mx(domain):

    try:
        dns.resolver.resolve(domain, 'MX')
        return True
    except:
        return False


# ---------------- SSL CHECK ----------------

def ssl_info(domain):

    try:

        context = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=3) as sock:

            with context.wrap_socket(sock, server_hostname=domain) as ssock:

                cert = ssock.getpeercert()

                issuer = dict(x[0] for x in cert['issuer'])

                expiry = datetime.strptime(
                    cert['notAfter'],
                    "%b %d %H:%M:%S %Y %Z"
                )

                valid_days = (expiry - datetime.utcnow()).days

                return issuer.get('organizationName', ''), valid_days

    except:

        return None, 0


# ---------------- HTML ANALYSIS ----------------

def analyze_html(url):

    try:

        response = requests.get(url, timeout=5)

        redirects = len(response.history)

        soup = BeautifulSoup(response.text, "html.parser")

        login_forms = len(soup.find_all("input", {"type": "password"}))
        iframes = len(soup.find_all("iframe"))
        scripts = len(soup.find_all("script"))

        return redirects, login_forms, iframes, scripts
  
    except:

        return 0, 0, 0, 0


# ---------------- ROUTES ----------------

@app.route('/')
def landing():
    return render_template("landing.html")


@app.route('/home')
def home():
    return render_template("index.html")


@app.route('/analyze', methods=['POST'])
def analyze():

    try:

        url = request.form['url']

        domain = extract_domain(url)

        total_score = 50

        explanation = {}

        # -------- FEATURE EXTRACTION --------

        domain_age = get_domain_age(domain)
        keywords_found = suspicious_keywords(url)
        url_length = len(url)
        https_flag = https_used(url)
        digits = digit_count(url)

        dns_flag = check_dns(domain)
        mx_flag = check_mx(domain)

        # -------- SCORING --------

        if "days" in domain_age:
            total_score -= 15
            explanation["Very New Domain"] = -15

        if "months" in domain_age:
            total_score -= 5
            explanation["Relatively New Domain"] = -5

        if not https_flag:
            total_score -= 10
            explanation["HTTPS Not Used"] = -10

        if len(keywords_found) > 0:
            total_score -= 10
            explanation["Suspicious Keywords"] = -10

        if not dns_flag:
            total_score -= 15
            explanation["No DNS Record"] = -15

        if not mx_flag:
            total_score -= 5
            explanation["No MX Record"] = -5

        issuer, valid_days = ssl_info(domain)

        if issuer and https_flag:
            total_score += 15
            explanation["Valid SSL Certificate"] = +15
        else:
            total_score -= 20
            explanation["No SSL Certificate"] = -20

        redirects, logins, iframes, scripts = analyze_html(url)

        if redirects > 3:
            total_score -= 10
            explanation["Too Many Redirects"] = -10

        if logins > 0 and not https_flag:
            total_score -= 10
            explanation["Login Form Without HTTPS"] = -10

        if iframes > 2:
            total_score -= 10
            explanation["Multiple Iframes"] = -10

        # -------- ML MODEL --------

        features_input = pd.DataFrame(
            [[url_length, url.count("."), url.count("-")]],
            columns=["length_url", "nb_dots", "nb_hyphens"]
        )

        try:

            prediction = model.predict(features_input)[0]

            if prediction == 0:
                total_score -= 15
                explanation["ML Model: Phishing Pattern"] = -15
            else:
                total_score += 10
                explanation["ML Model: Legitimate Pattern"] = +10

        except:
            pass

        # -------- FINAL SCORE --------

        total_score = max(0, min(100, total_score))

        if total_score <= 30:
            risk = "High Risk"
            recommendation = "⚠️ Avoid interacting with this website. It shows strong phishing indicators."

        elif total_score <= 60:
            risk = "Medium Risk"
            recommendation = "⚠️ Be cautious. Verify the website before entering personal information."

        elif total_score <= 85:
            risk = "Low Risk"
            recommendation = "ℹ️ Website appears mostly safe but remain careful with sensitive data."

        else:
            risk = "Safe"
            recommendation = "✅ Website appears safe based on the analysis."

        return render_template(
            "result.html",
            score=total_score,
            risk=risk,
            recommendation=recommendation,
            explanation=explanation,
            domain_age=domain_age,
            keywords=keywords_found,
            url_length=url_length,
            https_flag=https_flag,
            digits=digits,
            mx_flag=mx_flag
        )

    except Exception as e:

        return f"Error occurred: {str(e)}"


# ---------------- RUN APP ----------------

if __name__ == "__main__":
    app.run(debug=True)