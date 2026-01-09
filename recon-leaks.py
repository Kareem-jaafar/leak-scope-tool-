#!/usr/bin/env python3
import os, time, re, json, random, sys, requests, math, logging, urllib.parse
from datetime import datetime
from playwright.sync_api import sync_playwright, TimeoutError

C = {
    "CRITICAL": "\033[95m",
    "HIGH": "\033[91m",
    "MEDIUM": "\033[93m",
    "LOW": "\033[92m",
    "INFO": "\033[94m",
    "RESET": "\033[0m",
    "BOLD": "\033[1m"
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[
        logging.FileHandler("shadowscout.log", encoding="utf-8"),
        logging.StreamHandler(sys.stdout)
    ]
)

print(f"{C['INFO']}{C['BOLD']}ShadowScout AI - Advanced Recon & Leak Detection{C['RESET']}")
TARGET = input(f"{C['BOLD']}Target Domain : {C['RESET']}").strip()

print(f"{C['LOW']}{C['BOLD']}Author: kareem jaafar{C['RESET']}")

GITHUB_TOKEN = "your_github_token_here"

GOOGLE_DORKS = [
    'site:{d} filetype:env "DB_PASSWORD"',
    'site:{d} "BEGIN RSA PRIVATE KEY"',
    'site:{d} inurl:.git/config',
    'site:{d} intitle:"index of" "backup"',
    'site:{d} filetype:sql "dump"',
    'site:{d} "google_api_key"',
]

GITHUB_KEYWORDS = [
    "DB_PASSWORD",
    "DATABASE_URL",
    "AWS_SECRET_ACCESS_KEY",
    "api_key",
    "BEGIN RSA PRIVATE KEY"
]

RULES = [
    {"name": "Private Key", "regex": r"-----BEGIN (RSA|OPENSSH|EC) PRIVATE KEY-----", "risk": "CRITICAL"},
    {"name": "AWS Access Key", "regex": r"\bAKIA[0-9A-Z]{16}\b", "risk": "HIGH"},
    {"name": "Database URL", "regex": r"\b(mysql|postgres|mongodb|redis)://[^\s\"']+", "risk": "CRITICAL"},
    {"name": "Generic Password", "regex": r"\b(password|passwd|pwd)\s*[:=]\s*[^\s\"']{6,}", "risk": "MEDIUM"},
    {"name": "Firebase API Key", "regex": r"\bAIza[0-9A-Za-z\-_]{35}\b", "risk": "HIGH"}
]

BLACKLIST_EXTENSIONS = (".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2", ".ico")

def shannon_entropy(data):
    if not data:
        return 0
    freq = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0
    length = len(data)
    for c in freq:
        p = freq[c] / length
        entropy -= p * math.log2(p)
    return entropy

def high_entropy_string(s, threshold=4.0):
    return shannon_entropy(s) >= threshold

FOUND = []
PROCESSED = set()
START_TIME = time.time()
TOTAL_STEPS = len(GOOGLE_DORKS) + (len(GITHUB_KEYWORDS) if GITHUB_TOKEN != "your_github_token_here" else 0)
CURRENT_STEP = 0

def update_progress():
    global CURRENT_STEP
    CURRENT_STEP += 1
    elapsed = time.time() - START_TIME
    avg = elapsed / max(CURRENT_STEP, 1)
    remaining = avg * (TOTAL_STEPS - CURRENT_STEP)
    percent = int((CURRENT_STEP / TOTAL_STEPS) * 100)
    bar = "█" * (percent // 4)
    sys.stdout.write(f"\r{C['INFO']}[PROGRESS] |{bar:<25}| {percent}% ETA {int(remaining//60):02}:{int(remaining%60):02}{C['RESET']}")
    sys.stdout.flush()

def analyze_source(context, url):
    findings = []
    if url.lower().endswith(BLACKLIST_EXTENSIONS):
        return findings
    try:
        page = context.new_page()
        response = page.goto(url, timeout=25000, wait_until="domcontentloaded")
        if not response:
            page.close()
            return findings

        ctype = response.headers.get("content-type", "").lower()
        if any(x in ctype for x in ["image", "video", "pdf", "zip", "font"]):
            page.close()
            return findings

        content = page.content()
        if len(content) > 2_000_000:
            page.close()
            return findings

        for rule in RULES:
            matches = re.findall(rule["regex"], content, re.IGNORECASE)
            for m in matches:
                value = m if isinstance(m, str) else "".join(m)
                if len(value) >= 8 and high_entropy_string(value):
                    findings.append(rule)
                    break

        page.close()
    except TimeoutError:
        logging.warning(f"Timeout while analyzing {url}")
    except Exception as e:
        logging.error(f"Analyze error {url} | {e}")
    return findings

def run_google_engine(page, ctx):
    for dork in GOOGLE_DORKS:
        update_progress()
        query = dork.format(d=TARGET)
        try:
            page.goto("https://www.google.com", wait_until="networkidle")
            box = page.locator("textarea[name='q']")
            box.fill(query)
            page.keyboard.press("Enter")
            page.wait_for_selector("#search", timeout=10000)

            links = set()
            for a in page.query_selector_all("a"):
                href = a.get_attribute("href")
                if href and href.startswith("http") and TARGET in href:
                    links.add(href)

            for u in links:
                if u in PROCESSED:
                    continue
                PROCESSED.add(u)
                leaks = analyze_source(ctx, u)
                for f in leaks:
                    FOUND.append({"url": u, "type": f["name"], "risk": f["risk"], "source": "Google Source Analysis"})
                    print(f"\n{C[f['risk']]}[{f['risk']}] {f['name']} → {u}{C['RESET']}")
            time.sleep(random.uniform(5, 10))
        except Exception as e:
            logging.error(f"Google engine error | {e}")

def run_github_engine():
    if not GITHUB_TOKEN or "your" in GITHUB_TOKEN:
        return
    headers = {"Authorization": f"token {GITHUB_TOKEN}", "Accept": "application/vnd.github.v3+json"}
    for key in GITHUB_KEYWORDS:
        update_progress()
        q = urllib.parse.quote(f'{key} "{TARGET}"')
        url = f"https://api.github.com/search/code?q={q}"
        try:
            r = requests.get(url, headers=headers, timeout=15)
            if r.status_code == 200:
                for item in r.json().get("items", []):
                    FOUND.append({"url": item["html_url"], "type": "GitHub Code Leak", "risk": "HIGH", "source": "GitHub API"})
                    print(f"\n{C['HIGH']}[HIGH] GitHub Leak → {item['html_url']}{C['RESET']}")
            elif r.status_code == 403:
                logging.warning("GitHub rate limit hit")
                time.sleep(60)
        except Exception as e:
            logging.error(f"GitHub engine error | {e}")
        time.sleep(5)

def summary_report():
    stats = {}
    for f in FOUND:
        stats[f["risk"]] = stats.get(f["risk"], 0) + 1
    print("\n" + "-" * 60)
    print(f"{C['BOLD']}SUMMARY REPORT{C['RESET']}")
    for risk in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if risk in stats:
            print(f"{C[risk]}{risk}: {stats[risk]}{C['RESET']}")
    print("-" * 60)

def main():
    logging.info("Initializing environment")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
            viewport={"width": 1920, "height": 1080}
        )
        page = context.new_page()
        run_google_engine(page, context)
        run_github_engine()
        browser.close()

    print("\n" + "=" * 60)
    if FOUND:
        report = f"final_intel_{TARGET}.json"
        with open(report, "w", encoding="utf-8") as f:
            json.dump(FOUND, f, indent=4)
        print(f"{C['CRITICAL']}{C['BOLD']}SCAN COMPLETE: {len(FOUND)} FINDINGS{C['RESET']}")
        print(f"{C['INFO']}Report saved: {report}{C['RESET']}")
        summary_report()
    else:
        print(f"{C['LOW']}No public leaks detected for {TARGET}{C['RESET']}")
    print("=" * 60)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.warning("Scan interrupted by user")
