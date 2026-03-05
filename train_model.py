import pandas as pd
import os
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import sys

# ---------------- SAFE BASE PATH ----------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
csv_path = os.path.join(BASE_DIR, "dataset_phishing.csv")
model_path = os.path.join(BASE_DIR, "model.pkl")

# ---------------- CHECK FILE EXISTS ----------------
if not os.path.exists(csv_path):
    print("ERROR: dataset_phishing.csv not found in project folder.")
    sys.exit()

# ---------------- LOAD DATA ----------------
try:
    data = pd.read_csv(csv_path)
except Exception as e:
    print("Error reading CSV:", e)
    sys.exit()

# ---------------- REQUIRED FEATURES ----------------
FEATURES = [
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

# ---------------- CHECK COLUMNS ----------------
missing_columns = [col for col in FEATURES + ["status"] if col not in data.columns]

if missing_columns:
    print("ERROR: Missing columns in dataset:", missing_columns)
    sys.exit()

# ---------------- CLEAN DATA ----------------
data = data[FEATURES + ["status"]]
data = data.dropna()

data["status"] = data["status"].map({"legitimate": 1, "phishing": 0})

if data["status"].isnull().sum() > 0:
    print("ERROR: Invalid values found in status column.")
    sys.exit()

X = data[FEATURES]
y = data["status"]

# ---------------- TRAIN ----------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

model = RandomForestClassifier(
    n_estimators=150,
    random_state=42
)

model.fit(X_train, y_train)

accuracy = accuracy_score(y_test, model.predict(X_test))

print("Model Accuracy: {:.2f}%".format(accuracy * 100))

# ---------------- SAVE MODEL ----------------
try:
    with open(model_path, "wb") as f:
        pickle.dump(model, f)
    print("Model saved successfully as model.pkl")
except Exception as e:
    print("Error saving model:", e)