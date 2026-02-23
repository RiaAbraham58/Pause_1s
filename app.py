from flask import Flask, render_template, request
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

app = Flask(__name__)


data = pd.read_csv("dataset_phishing.csv")


features = [
    "length_url",
    "length_hostname",
    "nb_dots",
    "nb_hyphens",
    "nb_at",
    "nb_qm",
    "nb_www",
    "ratio_digits_url",
    "https_token"
]

data = data[features + ["status"]]

data["status"] = data["status"].map({
    "legitimate": 1,
    "phishing": 0
})

X = data.drop("status", axis=1)
y = data["status"]


model = RandomForestClassifier(n_estimators=150)
model.fit(X, y)


@app.route("/", methods=["GET", "POST"])
def home():
    trust_score = None
    message = ""

    if request.method == "POST":
        user_url = request.form["url"].lower()

        
        length_url = len(user_url)
        length_hostname = len(user_url.split("//")[-1].split("/")[0])
        nb_dots = user_url.count(".")
        nb_hyphens = user_url.count("-")
        nb_at = user_url.count("@")
        nb_qm = user_url.count("?")
        nb_www = user_url.count("www")

        digits = sum(c.isdigit() for c in user_url)
        ratio_digits_url = digits / len(user_url) if len(user_url) > 0 else 0

        https_token = 1 if "https" in user_url else 0

        features_input = np.array([[length_url,length_hostname,nb_dots,
                                    nb_hyphens,nb_at,nb_qm,nb_www,
                                    ratio_digits_url,https_token]])

        prediction = model.predict(features_input)[0]

    
        if prediction == 1:
            trust_score = 70
        else:
            trust_score = 30

        
        suspicious_words = [
            "free","gift","login","verify","update","bank",
            "password","bonus","win","urgent","account"
        ]

        if any(word in user_url for word in suspicious_words):
            trust_score -= 30

        
        if user_url.endswith(".xyz") or user_url.endswith(".ru") or user_url.endswith(".tk"):
            trust_score -= 25

        
        digit_count = sum(c.isdigit() for c in user_url)
        if digit_count > 5:
            trust_score -= 15

        
        if not user_url.startswith("https"):
            trust_score -= 10

        
        trust_score = max(0, min(100, trust_score))

        
        if trust_score >= 70:
            message = "Safe — You can enter personal data"
        elif trust_score >= 40:
            message = "Be cautious — Avoid sensitive data"
        else:
            message = "Dangerous — Do NOT enter personal data"

    return render_template("index.html",
                           score=trust_score,
                           message=message)

if __name__ == "__main__":
    app.run(debug=True)






