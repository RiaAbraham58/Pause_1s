# Pause 1s – Website Trust Meter for Phishing Detection

> **One second to analyze , one click to decide.**

## 📌 About the Project

**Pause 1s** is a web-based Website Trust Meter designed to help users assess the reliability of a website before interacting with it.

The system analyzes multiple website characteristics such as:

- HTTPS availability
- Domain age
- URL structure
- Suspicious keywords
- Domain extension
- DNS and SSL information

Based on these factors, the system generates a **Trust Score from 0–100** and provides a corresponding risk level and recommendations.

## ⚙️ How It Works

1. The user enters a website URL.
2. The system preprocesses and analyzes the URL.
3. Relevant security and URL features are extracted.
4. HTTPS, DNS, SSL and other website characteristics are checked.
5. Suspicious keywords and URL patterns are identified.
6. A trust score is calculated.
7. The user receives the score, risk level and recommendations.

## 🧠 Machine Learning

The project includes a literature-based study of machine learning approaches used for phishing URL detection.

The reviewed techniques include:

- Decision Tree
- Support Vector Machine (SVM)
- Naive Bayes
- Artificial Neural Network (ANN)
- Hybrid Machine Learning approaches
- Deep Learning approaches

These approaches use URL, domain and webpage-related features to distinguish between legitimate and phishing websites.

> **Note:** The current project report primarily describes a rule-based trust scoring mechanism. Random Forest is not explicitly documented as the implemented model in the report.

## 🛡️ Key Features

- 🔍 URL analysis
- 🔒 HTTPS security check
- 🌐 Domain information analysis
- 📅 Domain age evaluation
- ⚠️ Suspicious keyword detection
- 📊 Trust score from 0–100
- 🚨 Risk classification
- 💡 Security recommendations
- 🖥️ Simple web-based interface

## 📈 Risk Classification

| Trust Score | Risk Level |
|-------------|------------|
| 0–30 | 🔴 High Risk |
| 31–60 | 🟠 Medium Risk |
| 61–85 | 🟡 Low Risk |
| 86–100 | 🟢 Safe |

## 🛠️ Technologies Used

### Frontend
- HTML
- CSS
- JavaScript

### Backend
- Python
- Flask

### Python Libraries
- Requests
- BeautifulSoup
- Whois
- SSL
- Socket

### Development Tool
- Visual Studio Code

## 🏗️ System Modules

### 1. Frontend Module
Provides the interface for entering a URL and displaying the analysis results.

### 2. Backend Analysis Module
Performs URL preprocessing, feature extraction, content analysis and security checks.

### 3. Result Module
Displays the calculated trust score, risk level, extracted features and recommendations.

## 🔮 Future Enhancements

Future improvements may include:

- Domain reputation analysis
- Hosting information
- Certificate Authority validation
- Threat intelligence integration
- User feedback mechanisms
- Browser extension

- Mobile compatibility

## 👩‍💻 Project Team

- **Ria Mary Abraham**
- **Shemil Thomas**
- **Thrisha V**

## 🎓 Academic Project

**B.Tech CSE – Cyber Security**  
**Muthoot Institute of Technology and Science**


