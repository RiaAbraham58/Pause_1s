import pandas as pd
import random

data = pd.read_csv("dataset_phishing.csv")


def convert_to_trust(label):
    if label == "legitimate":
        return random.randint(70, 100)
    else:
        return random.randint(0, 39)

data["trust_score"] = data["status"].apply(convert_to_trust)

print(data[["status","trust_score"]].head())


data = data.drop(["url", "status"], axis=1)


X = data.drop("trust_score", axis=1)
y = data["trust_score"]


from sklearn.model_selection import train_test_split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)


from sklearn.ensemble import RandomForestRegressor
model = RandomForestRegressor(n_estimators=100)
model.fit(X_train, y_train)


predictions = model.predict(X_test)
print("Sample Predictions:", predictions[:5])

print("\n======= AI WEBSITE TRUST ANALYZER =======")
user_url = input("Enter website URL: ").lower()


trusted_domains = [
    "google.com","amazon.com","microsoft.com",
    "apple.com","github.com","wikipedia.org",
    "facebook.com","instagram.com","linkedin.com"
]

if any(domain in user_url for domain in trusted_domains):
    print("\nTrust Score: 95")
    print("Safe Website (Highly Trusted Domain)")
    exit()


url_length = len(user_url)
hostname_length = len(user_url.split("//")[-1].split("/")[0])
digit_count = sum(c.isdigit() for c in user_url)
special_char_count = user_url.count("@") + user_url.count("-") + user_url.count("?")
has_https = 1 if "https" in user_url else 0
has_ip = 1 if any(char.isdigit() for char in user_url.split("/")[2] if char.isdigit()) else 0


suspicious_words = ["login","verify","update","bank","free","gift","password","urgent"]
suspicious_count = sum(word in user_url for word in suspicious_words)

import numpy as np


input_features = np.zeros((1, X.shape[1]))
input_features[0][0] = url_length
input_features[0][1] = hostname_length
input_features[0][2] = digit_count
input_features[0][3] = special_char_count
input_features[0][4] = has_https


predicted_score = model.predict(input_features)[0]


predicted_score -= suspicious_count * 5
if has_ip:
    predicted_score -= 15

predicted_score = max(0, min(100, predicted_score))

print("\n Trust Score:", int(predicted_score))

if predicted_score >= 75:
    print(" Safe Website")
elif predicted_score >= 40:
    print(" Suspicious — Be Cautious")
else:
    print("Dangerous — Do NOT enter personal data")






