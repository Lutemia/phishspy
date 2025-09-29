# PhishSpy

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](#license)  
[![Python Version](https://img.shields.io/badge/python-3.x-brightgreen.svg)](#installation)  

A Python + Tkinter desktop app that helps SOC / Security Analysts rapidly check suspicious URLs, IPs, and domains using the VirusTotal API.

---

## 📂 Table of Contents

- [Overview](#overview)  
- [Features](#features)  
- [Examples](#examples)  
- [Installation](#installation)  
- [Usage](#usage)  
- [Roadmap](#roadmap)  


---

## 🧠 Overview

This tool is built to assist security operations teams by providing a simple GUI-based interface for doing reputation checks on IOCs (Indicators of Compromise) including: URLs, IP addresses, and domains using the VirusTotal API. It offers quick insight (malicious, suspicious, harmless, undetected) to help analysts triage threats faster.

---

## ✨ Features

- ✅ Check a single URL, IP, or domain  
- 🖥️ Graphical UI built with Tkinter + ttk
- 📊 Displays verdicts: malicious, suspicious, harmless, undetected  
- 🛠️ Easily extensible to add file/attachment scanning, batch checks, or integrations  

---

## 📌 Examples

Here’s how you might use the app in practice:

**As a user (via GUI):**

1. Enter `http://example.com`  
2. Select **URL** type  
3. Click **Check**  
4. See output:

---

## 🛠️ Installation
```bash
git clone https://github.com/yourusername/email-threat-checker.git
cd email-threat-checker
pip install requests
```
Then, in main.py, set your VirusTotal API key:

```python
VT_API_KEY = "YOUR_API_KEY_HERE"
```

Finally, run:
```
python main.py
```

---

## 🧭 Usage

Enter the IOC (URL, IP, or domain)

Select its type

Click Check

Review the verdict stats returned

Use results to help triage and decide next steps

---

## 📈 Roadmap

 Add file upload / hash scanning

 Add batch processing (multiple IOCs at once)

 Export results (CSV / JSON)

 Integrate with SIEM / SOAR / alerts

 Theming / dark mode for GUI
