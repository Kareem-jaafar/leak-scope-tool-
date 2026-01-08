#!/usr/bin/env python3
import os, time, re, json, random
from datetime import datetime
from playwright.sync_api import sync_playwright

# =======================================================
# Terminal Colors
# =======================================================
COLORS = {
    "CRITICAL": "\033[95m",  # بنفسجي داكن
    "HIGH":     "\033[91m",  # أحمر
    "MEDIUM":   "\033[93m",  # أصفر
    "LOW":      "\033[92m",  # أخضر
    "INFO":     "\033[94m",  # أزرق
    "RESET":    "\033[0m"
}

# =======================================================
# Banner
# =======================================================
print(f"""
=======================================================
 {COLORS["HIGH"]}LeakScope – Public Exposure Intelligence Tool{COLORS["RESET"]}
 Author : Kareem Jaafar
 Purpose: Passive OSINT-based Security Assessment
=======================================================
""")

# =======================================================
# 1. Google Dorks Collection
# =======================================================
DORKS_COLLECTION = {
    "Config & Environment": [
        'site:{d} filetype:env "DB_PASSWORD="',
        'site:{d} filetype:json "AWS_SECRET_ACCESS_KEY="',
        'site:{d} filetype:config "connectionString="',
        'site:{d} filetype:ini "db_pass"',
        'site:{d} "BEGIN RSA PRIVATE KEY"',
        'site:{d} "BEGIN OPENSSH PRIVATE KEY"'
    ],
    "Advanced": [
        'site:{d} inurl:.git/config',
        'site:{d} intitle:"index of" ".ssh"',
        'site:{d} "docker-compose.yml" "password"',
        'site:s3.amazonaws.com "{d}"',
        'site:blob.core.windows.net "{d}"'
    ],
    "Credentials": [
        'site:{d} intext:"password" "login"',
        'site:pastebin.com "{d}" "password"',
        'site:github.com "{d}" "apikey"'
    ],
    "Backups & Dumps": [
        'site:{d} intitle:"index of" "backup"',
        'site:{d} filetype:sql "dump"',
        'site:{d} filetype:bak OR filetype:old'
    ]
}

# =======================================================
# 2. Memory & Statistics
# =======================================================
PROCESSED_URLS = set()
STATS = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
SCREENSHOT_DIR = "leaks_evidence"
os.makedirs(SCREENSHOT_DIR, exist_ok=True)

# =======================================================
# 3. Detection Rules
# =======================================================
RULES = [
    {
        "name": "Private Key",
        "regex": r"BEGIN (RSA|OPENSSH) PRIVATE KEY",
        "risk": "HIGH"
    },
    {
        "name": "AWS Access Key",
        "regex": r"AKIA[0-9A-Z]{16}",
        "risk": "HIGH"
    },
    {
        "name": "Database Credentials",
        "regex": r"(DB_PASSWORD|DATABASE_URL)\s*=",
        "risk": "CRITICAL"
    },
    {
        "name": "Generic Password",
        "regex": r"password\s*[:=]\s*[^\s]+",
        "risk": "MEDIUM"
    }
]

# =======================================================
# Utility: Colored Risk Print
# =======================================================
def print_risk(level, message):
    color = COLORS.get(level, COLORS["RESET"])
    print(f"{color}[{level}]{COLORS['RESET']} {message}")

# =======================================================
# 4. Human-like Behavior
# =======================================================
def human_mouse_move(page, sx, sy, ex, ey, steps=15):
    cx = (sx + ex) / 2 + random.randint(-50, 50)
    cy = (sy + ey) / 2 + random.randint(-50, 50)
    for i in range(steps + 1):
        t = i / steps
        x = (1-t)**2 * sx + 2*(1-t)*t * cx + t**2 * ex
        y = (1-t)**2 * sy + 2*(1-t)*t * cy + t**2 * ey
        page.mouse.move(x, y)
        time.sleep(random.uniform(0.01, 0.02))

def human_type(element, text):
    element.click()
    for c in text:
        element.type(c, delay=random.randint(60, 180))
        if random.random() > 0.96:
            time.sleep(0.4)

# =======================================================
# 5. Google Search (Headless)
# =======================================================
def headless_google_search(page, query):
    results = []
    try:
        page.goto("https://www.google.com", wait_until="networkidle")
        if page.query_selector("button:has-text('Accept all')"):
            page.click("button:has-text('Accept all')")

        box = page.locator("textarea[name='q']")
        human_type(box, query)
        page.keyboard.press("Enter")
        page.wait_for_selector("#search", timeout=12000)
        human_mouse_move(page, 100, 100, random.randint(400, 800), random.randint(300, 700))

        for r in page.query_selector_all('div[data-ved]'):
            t = r.query_selector("h3")
            a = r.query_selector("a")
            if t and a:
                results.append({
                    "title": t.inner_text(),
                    "link": a.get_attribute("href")
                })
    except:
        pass

    return [r for r in results if r.get("link", "").startswith("http")]

# =======================================================
# 6. Page Analysis
# =======================================================
def extract_page_text(context, url):
    try:
        page = context.new_page()
        page.goto(url, timeout=30000, wait_until="load")
        page.wait_for_timeout(2000)
        text = page.evaluate("() => document.body.innerText || ''")
        page.close()
        return text.strip()
    except:
        return ""

def classify(text):
    return [r for r in RULES if re.search(r["regex"], text, re.IGNORECASE)]

def capture_leak_screenshot(context, url, risk):
    try:
        page = context.new_page()
        page.goto(url, timeout=30000, wait_until="load")
        path = os.path.join(
            SCREENSHOT_DIR,
            f"{risk}_{int(time.time())}.png"
        )
        page.screenshot(path=path)
        page.close()
        return path
    except:
        return None

# =======================================================
# 7. Executive Summary
# =======================================================
def print_executive_summary(domain):
    print("\n" + "=" * 55)
    print(f"📊 EXECUTIVE SUMMARY FOR: {domain}")
    print(f"🕒 Scan Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 55)

    icons = {
        "CRITICAL": "💀",
        "HIGH": "🔴",
        "MEDIUM": "🟠",
        "LOW": "🟢"
    }

    for level, count in STATS.items():
        color = COLORS.get(level, COLORS["RESET"])
        print(f"{color}{icons[level]} {level:<8} : {count}{COLORS['RESET']}")

    print("=" * 55 + "\n")

# =======================================================
# 8. Main Engine
# =======================================================
def main(domain):
    report = []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        )
        page = context.new_page()

        for category, dorks in DORKS_COLLECTION.items():
            for dork in dorks:
                query = dork.format(d=domain)
                results = headless_google_search(page, query)

                for r in results:
                    url = r["link"]
                    if url in PROCESSED_URLS:
                        continue
                    PROCESSED_URLS.add(url)

                    content = extract_page_text(context, url)
                    if not content:
                        continue

                    hits = classify(content)
                    for h in hits:
                        risk = h["risk"]
                        STATS[risk] += 1

                        print_risk(
                            risk,
                            f"{h['name']} detected at {url}"
                        )

                        evidence = (
                            capture_leak_screenshot(context, url, risk)
                            if risk in ["HIGH", "CRITICAL"]
                            else None
                        )

                        report.append({
                            "url": url,
                            "type": h["name"],
                            "risk": risk,
                            "evidence": evidence,
                            "timestamp": datetime.utcnow().isoformat()
                        })

                time.sleep(random.uniform(6, 10))

        browser.close()

    print_executive_summary(domain)

    with open(f"final_intel_{domain}.json", "w") as f:
        json.dump(report, f, indent=2)

# =======================================================
# Entry Point
# =======================================================
if __name__ == "__main__":
    target = input("Target Domain (example.com): ").strip()
    main(target)
