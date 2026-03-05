from flask import Flask, render_template, request
import os
import pickle
import requests
import socket
import ssl
import dns.resolver
import re
import whois
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
SUSPICIOUS_TLDS = ["xyz", "top", "tk", "ru", "click", "gq"]

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure",
    "bank", "account", "password", "free", "bonus"
]

BRANDS = {
    "amazon": ["amazon.com", "amazon.in"],
    "google": ["google.com"],
    "microsoft": ["microsoft.com"],
    "sbi": ["sbi.co.in"],
    "icici": ["icicibank.com"]
}

# ---------------- UTILITIES ----------------

def extract_domain(url):
    if not url.startswith("http"):
        url = "http://" + url
    return urlparse(url).netloc.lower()

def is_ip(domain):
    return re.match(r"\d+\.\d+\.\d+\.\d+", domain) is not None

def count_subdomains(domain):
    return len(domain.split(".")) - 2

def detect_unicode(domain):
    try:
        domain.encode("ascii")
        return False
    except:
        return True

def suspicious_tld(domain):
    tld = domain.split(".")[-1]
    return tld in SUSPICIOUS_TLDS

def brand_mismatch(domain):
    for brand, official_domains in BRANDS.items():
        if brand in domain and domain not in official_domains:
            return True
    return False

def check_dns(domain):
    try:
        dns.resolver.resolve(domain, 'A')
        return True
    except:
        return False

def check_mx(domain):
    try:
        dns.resolver.resolve(domain, 'MX')
        return True
    except:
        return False

def ssl_info(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert['issuer'])
                expiry = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                valid_days = (expiry - datetime.utcnow()).days
                return issuer.get('organizationName', ''), valid_days
    except:
        return None, 0

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

def get_domain_age(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            age = (datetime.utcnow() - creation_date).days // 365
            return age
        return "Unavailable"
    except:
        return "Unavailable"

def suspicious_keywords(url):
    found = []
    for word in SUSPICIOUS_KEYWORDS:
        if word in url.lower():
            found.append(word)
    return found

def https_used(url):
    return url.startswith("https")

def digit_count(url):
    return sum(c.isdigit() for c in url)

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

        # -------- EXTRA FEATURES --------
        domain_age = get_domain_age(domain)
        keywords_found = suspicious_keywords(url)
        url_length = len(url)
        https_flag = https_used(url)
        digits = digit_count(url)

        if isinstance(domain_age, int) and domain_age < 1:
            total_score -= 20
            explanation["Domain Age < 1 Year"] = -20

        if len(keywords_found) > 0:
            total_score -= 10
            explanation["Suspicious Keywords"] = -10

        if not https_flag:
            total_score -= 10
            explanation["HTTPS Not Used"] = -10

        # -------- URL STRUCTURE --------
        if is_ip(domain):
            total_score -= 20
            explanation["IP Address Used"] = -20

        if count_subdomains(domain) > 2:
            total_score -= 10
            explanation["Excess Subdomains"] = -10

        if suspicious_tld(domain):
            total_score -= 15
            explanation["Suspicious TLD"] = -15

        if detect_unicode(domain):
            total_score -= 15
            explanation["Unicode Domain"] = -15

        # -------- BRAND --------
        if brand_mismatch(domain):
            total_score -= 30
            explanation["Brand Mismatch"] = -30

        # -------- DNS --------
        if not check_dns(domain):
            total_score -= 15
            explanation["No DNS Record"] = -15

        if not check_mx(domain):
            total_score -= 5
            explanation["No MX Record"] = -5

        # -------- SSL --------
        issuer, valid_days = ssl_info(domain)
        if issuer:
            total_score += 10
            explanation["Valid SSL"] = +10
            if valid_days < 30:
                total_score -= 10
                explanation["SSL Expiring Soon"] = -10
        else:
            total_score -= 20
            explanation["No SSL"] = -20

        # -------- CONTENT --------
        redirects, logins, iframes, scripts = analyze_html(url)

        if redirects > 3:
            total_score -= 10
            explanation["Too Many Redirects"] = -10

        if logins > 0:
            total_score -= 10
            explanation["Login Form Detected"] = -10

        if iframes > 2:
            total_score -= 10
            explanation["Multiple Iframes"] = -10

        if scripts > 20:
            total_score -= 5
            explanation["Heavy Script Usage"] = -5

        # -------- ML LAYER --------
        features_input = pd.DataFrame(
            [[url_length, url.count("."), url.count("-")]],
            columns=["length_url", "nb_dots", "nb_hyphens"]
        )

        try:
            prediction = model.predict(features_input)[0]
            if prediction == 0:
                total_score -= 15
                explanation["ML Phishing Prediction"] = -15
            else:
                total_score += 10
                explanation["ML Legitimate Prediction"] = +10
        except:
            pass

        # -------- FINAL SCORE --------
        total_score = max(0, min(100, total_score))

        if total_score <= 30:
            risk = "High Risk"
        elif total_score <= 60:
            risk = "Medium Risk"
        elif total_score <= 85:
            risk = "Low Risk"
        else:
            risk = "Safe"

        return render_template(
            "result.html",
            url=url,
            score=total_score,
            risk=risk,
            explanation=explanation,
            domain_age=domain_age,
            keywords=keywords_found,
            url_length=url_length,
            https_flag=https_flag,
            digits=digits
        )

    except Exception as e:
        return f"Error occurred: {str(e)}"

# ---------------- RUN APP ----------------
if __name__ == "__main__":
    app.run(debug=True)