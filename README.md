# leak-scope-tool-
LeakScope is a passive OSINT tool that identifies and classifies publicly exposed sensitive information across internet-facing assets for security assessment and responsible disclosure.
> ⚠️ LeakScope performs **passive reconnaissance only**.  
> It does **NOT** exploit vulnerabilities, brute-force systems, or bypass authentication.

---

## ✨ Features

- 🔎 Advanced Google Dorks collection (Configs, Credentials, Backups, Cloud, Secrets)
- 🧠 Intelligent content classification using regex-based rules
- 🎯 Risk severity levels: **LOW / MEDIUM / HIGH / CRITICAL**
- 🎨 Colored terminal output for instant risk awareness
- 📸 Automatic screenshot evidence for High & Critical findings
- 🧾 JSON executive report generation
- 🕵️ Human-like browsing behavior (anti-detection)
- ♻️ Duplicate URL prevention (memory-based)
- 📊 Executive summary at scan completion

---

## 🧠 Use Cases

- Bug Bounty reconnaissance
- Passive asset exposure discovery
- Security posture assessment
- Red Team OSINT phase
- Blue Team exposure monitoring

## ⚙️ Requirements

- Python 3.9+
- Google Chrome / Chromium
- Playwright

Install dependencies:
```bash
pip install playwright
playwright install chromium

## Download 
git clone https://github.com/Kareem-jaafar/leak-scope-tool-.git
