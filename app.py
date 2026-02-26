from flask import Flask, render_template, request
import whois
from datetime import datetime
from urllib.parse import urlparse
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

app = Flask(__name__)

# ---------------- LOAD DATA ----------------
data = pd.read_csv("dataset_phishing.csv")

features = [
    "length_url","length_hostname","nb_dots","nb_hyphens",
    "nb_at","nb_qm","nb_www","ratio_digits_url","https_token"
]

data = data[features + ["status"]]
data["status"] = data["status"].map({"legitimate": 1, "phishing": 0})

X = data.drop("status", axis=1)
y = data["status"]

model = RandomForestClassifier(n_estimators=150, random_state=42)
model.fit(X, y)

# ---------------- DOMAIN FUNCTIONS ----------------
def extract_domain(user_url):
    if not user_url.startswith("http"):
        user_url = "http://" + user_url
    domain = urlparse(user_url).netloc
    return domain[4:] if domain.startswith("www.") else domain

def get_domain_age(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if not creation_date:
            return 0
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(creation_date, str):
            creation_date = datetime.strptime(creation_date[:10], "%Y-%m-%d")
        return max(datetime.now().year - creation_date.year, 0)
    except:
        return 0

# ---------------- ROUTES ----------------
@app.route('/')
def landing():
    return render_template("landing.html")

@app.route('/home', methods=["GET","POST"])
def home():
    return render_template("index.html")

@app.route('/analyze', methods=['POST'])
def analyze():
    user_url = request.form.get("url","").lower()
    if not user_url:
        return render_template("index.html", error="Please enter a valid URL")

    # --- Feature extraction ---
    length_url = len(user_url)
    hostname = user_url.split("//")[-1].split("/")[0]
    length_hostname = len(hostname)
    nb_dots = user_url.count(".")
    nb_hyphens = user_url.count("-")
    nb_at = user_url.count("@")
    nb_qm = user_url.count("?")
    nb_www = user_url.count("www")
    digit_count = sum(c.isdigit() for c in user_url)
    ratio_digits_url = digit_count / len(user_url)
    https_token = 1 if user_url.startswith("https") else 0

    features_input = pd.DataFrame([[
        length_url, length_hostname, nb_dots, nb_hyphens,
        nb_at, nb_qm, nb_www, ratio_digits_url, https_token
    ]], columns=model.feature_names_in_)

    prediction = model.predict(features_input)[0]
    probability = model.predict_proba(features_input)[0][1]

    # ---------------- HYBRID TRUST SCORING ----------------
    trust_score = 60 if prediction==1 else 30
    trust_score += int(probability*25)

    # HTTPS check
    trust_score += 10 if user_url.startswith("https") else -10

    # Domain age
    domain = extract_domain(user_url)
    domain_age = get_domain_age(domain)
    if domain_age >= 10:
        trust_score += 20
    elif domain_age >= 5:
        trust_score += 15
    elif domain_age >= 3:
        trust_score += 10
    elif domain_age >= 1:
        trust_score -= 5
    else:
        trust_score -= 10

    # Suspicious keywords
    suspicious_words = ["login","verify","update","secure","account","bank","free","gift"]
    keyword_count = sum(word in user_url for word in suspicious_words)
    if keyword_count >= 3: trust_score -= 20
    elif keyword_count == 2: trust_score -= 10
    elif keyword_count == 1: trust_score -= 5

    # Final adjustments
    trust_score = max(15, min(100, trust_score))
    if trust_score >= 75:
        message = "Safe — Website shows strong trust indicators."
    elif trust_score >= 45:
        message = "Caution — Some risk indicators detected."
    else:
        message = "Dangerous — Multiple suspicious signals found."

    # Technical details
    technical = {
        "HTTPS Used": "Yes" if user_url.startswith("https") else "No",
        "URL Length": length_url,
        "Digits Count": digit_count,
        "Domain Age (years)": f"{domain_age} years" if domain_age>0 else "Less than 1 year/Unavailable",
        "Model Prediction": "Legitimate" if prediction==1 else "Phishing"
    }

    return render_template("result.html",
                           url=user_url,
                           score=trust_score,
                           message=message,
                           technical=technical)

if __name__ == "__main__":
    app.run(debug=True)