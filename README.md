<p align="center">
  <img src="https://img.shields.io/badge/LinkGuard-Offline%20Phishing%20Detection%20Toolkit-000000?style=for-the-badge&logo=hackaday&logoColor=red&labelColor=000000&color=8B0000" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Mode-Offline%20Analysis-8B0000?style=flat-square&logo=shield&logoColor=white"/>
  <img src="https://img.shields.io/badge/Detection-Heuristic%20Based-000000?style=flat-square&logo=protonvpn&logoColor=red"/>
  <img src="https://img.shields.io/badge/Python-3.9%2B-8B0000?style=flat-square&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/UI-CustomTkinter-000000?style=flat-square"/>
  <img src="https://img.shields.io/badge/Status-Active-8B0000?style=flat-square"/>
</p>

---

# 🔗 LinkGuard

> **Fully Offline Phishing URL Detection Toolkit With Intelligent Risk Scoring**

LinkGuard Is A **Local-First Cybersecurity Tool** That Detects Phishing URLs Using **Domain Intelligence, Heuristics, And Entropy Analysis** — Without Any External APIs Or Online Services.

---

## 🧠 Core Capabilities

- 🔍 **Offline URL Analysis Engine**
- 🧩 **Heuristic-Based Detection System**
- 🌐 **Domain Intelligence Processing**
- 🧠 **Entropy-Based Obfuscation Detection**
- 📊 **Risk Scoring (LOW / MEDIUM / HIGH)**
- 📁 **JSON Report Generation**
- 🖥️ **CLI + GUI Support (CustomTkinter)**

---

## 🔍 Detection Techniques

- URL Normalization And Protocol Validation  
- Typosquatting And Brand Spoof Detection  
- Subdomain Abuse Analysis  
- IP-Based URL Detection  
- Suspicious Patterns:
  - Keywords
  - Long URLs
  - Excessive Dots / Hyphens
  - Encoded Characters  
- Entropy Analysis For Obfuscation  

---

## ⚙️ Requirements

- Python **3.9 Or Higher**
- `customtkinter` *(For GUI Mode)*

Install Dependencies:

```bash
pip install -r requirements.txt
```

---

## ▶️ Usage

### 🔹 Single URL Scan
```bash
python main.py -u "http://amaz0n-login-secure.xyz"
```

### 🔹 Batch Scan
```bash
python main.py -f urls.txt
```

### 🔹 Save JSON Report
```bash
python main.py -u "http://amaz0n-login-secure.xyz" -s
```

### 🔹 Interactive Mode
```bash
python main.py
```

### 🔹 GUI Mode (CustomTkinter)
```bash
python main.py --ui
```

### 🔹 Run UI Module Directly
```bash
python linkguard/ui.py
```

---

## 📁 Project Structure

```
linkguard/
  main.py
  analyzer/
    domain_check.py
    pattern_check.py
    entropy.py
    scorer.py
  utils/
    helpers.py
  data/
    whitelist.json
    blacklist.json
  reports/
```

---

## 🧪 Sample Test URLs

- `http://amaz0n-login-secure.xyz`  
- `https://login.microsoft.com.verify-user.account-update.ru`  
- `http://192.168.1.15/secure/login`  
- `https://github.com`  

---

## ⚠️ Notes

- Add Trusted Domains To `linkguard/data/whitelist.json`  
- Add Malicious Domains Or Patterns To `linkguard/data/blacklist.json`  
- Reports Are Saved In `linkguard/reports/` When `-s` Is Used  
- Brand List For Detection Can Be Extended In `domain_check.py`  

---

## ⚖️ Accuracy Philosophy

LinkGuard Uses **Multi-Signal Analysis And Conservative Scoring** To Reduce False Positives While Still Detecting Common Phishing Techniques.  

Scoring Logic Can Be Tuned In:

```
linkguard/analyzer/scorer.py
```

---

## 🪟 Windows Setup (PowerShell)

```powershell
python -m venv venv
venv\Scripts\Activate.ps1
pip install -r requirements.txt
python main.py --ui
```

---

## 🐧 Linux / 🍎 macOS Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python main.py --ui
```

---

## 💻 Terminal-Only Usage

```bash
python main.py -u "https://example.com"
```

---

## 👨‍💻 Author

- **Arjun Bohara**

---

<p align="center">
  <img src="https://img.shields.io/badge/Built%20For-Defenders-000000?style=for-the-badge&logo=ghost&logoColor=red"/>
  <img src="https://img.shields.io/badge/Powered%20By-Python-8B0000?style=for-the-badge&logo=python&logoColor=white"/>
</p>

---

> 🔗 **LinkGuard — Detect Before You Click.**
