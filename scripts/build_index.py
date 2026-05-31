import requests
import os
import sys
import json
from dotenv import load_dotenv
from bs4 import BeautifulSoup
from datetime import date

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.tools.vector_tools import load_corpus, build_index # apare subliniat cu rosu dar merge....
import chromadb

load_dotenv()
today = date.today().isoformat()
# https://nvd.nist.gov/developers/vulnerabilities
# https://owasp.org/Top10/2025/

# RULEAZA DIN MAIN DIR TERMINAL

def filter_cvss(cves: list, min_score: float = 7.0, limit: int = 4):
    res = []
    for c in cves:
        try:
            score = c["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]
            if score >= min_score:
                res.append(c)
                if len(res) == limit:
                    break
        except (KeyError, IndexError):
            pass
    return res


# A02 - Security Misconfiguration
resp_a02 = requests.get(
    "https://services.nvd.nist.gov/rest/json/cves/2.0",
    params={"keywordSearch": "misconfiguration", "cvssV3Severity": "HIGH", "resultsPerPage": 50},
    headers={"apiKey": os.getenv("NVD_API_KEY")}
)

# A04 - Cryptographic Failures
resp_a04 = requests.get(
    "https://services.nvd.nist.gov/rest/json/cves/2.0",
    params={"keywordSearch": "python ssl", "cvssV3Severity": "HIGH", "resultsPerPage": 50},
    headers={"apiKey": os.getenv("NVD_API_KEY")}
)

# A05 - Injection
resp_a05 = requests.get(
    "https://services.nvd.nist.gov/rest/json/cves/2.0",
    params={"keywordSearch": "django sql injection", "cvssV3Severity": "CRITICAL", "resultsPerPage": 50},
    headers={"apiKey": os.getenv("NVD_API_KEY")}
)

# A07 - Authentication Failures
resp_a07 = requests.get(
    "https://services.nvd.nist.gov/rest/json/cves/2.0",
    params={"keywordSearch": "Python authentication bypass", "cvssV3Severity": "HIGH", "resultsPerPage": 50},
    headers={"apiKey": os.getenv("NVD_API_KEY")}
)

cves_a02 = filter_cvss(resp_a02.json()["vulnerabilities"])
cves_a04 = filter_cvss(resp_a04.json()["vulnerabilities"])
cves_a05 = filter_cvss(resp_a05.json()["vulnerabilities"])
cves_a07 = filter_cvss(resp_a07.json()["vulnerabilities"])
print(f"A02: {len(resp_a02.json()['vulnerabilities'])} total, {len(cves_a02)} dupa filtrare")
print(f"A04: {len(resp_a04.json()['vulnerabilities'])} total, {len(cves_a04)} dupa filtrare")
print(f"A05: {len(resp_a05.json()['vulnerabilities'])} total, {len(cves_a05)} dupa filtrare")
print(f"A07: {len(resp_a07.json()['vulnerabilities'])} total, {len(cves_a07)} dupa filtrare")


all_cve = cves_a02 + cves_a04 + cves_a05 + cves_a07
for cve in all_cve:
    cve_id = cve["cve"]["id"]
    try:
        score = cve["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]
    except (KeyError, IndexError):
        score = "N/A"
    with open(f"./corpus/cve/{cve_id}.json", "w", encoding="utf-8") as f:
        json.dump(cve, f, indent=2)

# https://owasp.org/Top10/2025/
URLS = {
    "A01_2025-Broken_Access_Control":         "https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/",
    "A02_2025-Security_Misconfiguration":      "https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/",
    "A03_2025-Software_Supply_Chain_Failures": "https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/",
    "A04_2025-Cryptographic_Failures":         "https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/",
}

for key, url in URLS.items():
    resp = requests.get(url)
    soup = BeautifulSoup(resp.text, "html.parser")
    content = soup.find("article")
    text = f"# {key}\n# Sursa: {url}\n# Data accesarii: {today}\n\n"
    text += content.get_text(separator="\n", strip=True)
    with open(f"./corpus/owasp/{key}.md", "w", encoding="utf-8") as f:
        f.write(text)

# https://cwe.mitre.org/data/definitions/89.html
cwe_URLS = {
    "CWE-89_sql_injection":   "https://cwe.mitre.org/data/definitions/89.html",
    "CWE-79_xss":             "https://cwe.mitre.org/data/definitions/79.html",
    "CWE-502_deserialization":"https://cwe.mitre.org/data/definitions/502.html",
}

for key, url in cwe_URLS.items():
    resp = requests.get(url)
    soup = BeautifulSoup(resp.text, "html.parser")
    sections = [
        "Description", "Alternate_Terms", "Potential_Mitigations",
        "Relationships", "Modes_Of_Introduction", "Applicable_Platforms",
        "Demonstrative_Examples", "Detection_Methods"
    ]
    text = f"# {key}\n# Sursa: {url}\n# Data accesarii: {today}\n"
    for s in sections:
        div = soup.find("div", {"id": s})
        if div:
            text += f"\n## {s}\n"
            text += div.get_text(separator="\n", strip=True)
    with open(f"./corpus/cwe/{key}.md", "w", encoding="utf-8") as f:
        f.write(text)

# https://docs.djangoproject.com/en/stable/topics/security/
django_url = "https://docs.djangoproject.com/en/stable/topics/security/"
resp = requests.get(django_url)
soup = BeautifulSoup(resp.text, "html.parser")
sectiuni = {
    "django_xss":    "s-cross-site-scripting-xss-protection",
    "django_upload": "s-user-uploaded-content",
    "django_ssl":    "s-ssl-https",
}

for key, section_id in sectiuni.items():
    content = soup.find("section", {"id": section_id})
    if content:
        text = f"# {key}\n# Sursa: {django_url}\n# Data accesarii: {today}\n\n"
        text += content.get_text(separator="\n", strip=True)
        with open(f"./corpus/framework_docs/{key}.md", "w", encoding="utf-8") as f:
            f.write(text)

# https://peps.python.org/pep-0008/
# https://google.github.io/styleguide/pyguide.html
style_guides = {
    "pep8":         "https://peps.python.org/pep-0008/",
    "google_style": "https://google.github.io/styleguide/pyguide.html",
}

for key, url in style_guides.items():
    resp = requests.get(url)
    soup = BeautifulSoup(resp.text, "html.parser")
    content = soup.find("main") or soup.find("article") or soup.find("body")
    text = f"# {key}\n# Sursa: {url}\n# Data accesarii: {today}\n\n"
    text += content.get_text(separator="\n", strip=True)
    with open(f"./corpus/style_guides/{key}.md", "w", encoding="utf-8") as f:
        f.write(text)

# sources.md - documentatie pentru evaluare
lines = [
    f"# Surse corpus\n",
    f"Data accesarii: {today}\n\n",
    "## CVE-uri NVD\n"
]
for cve in all_cve:
    cve_id = cve["cve"]["id"]
    try:
        score = cve["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]
    except (KeyError, IndexError):
        score = "N/A"
    lines.append(f"- {cve_id} | CVSS: {score} | https://nvd.nist.gov/vuln/detail/{cve_id}\n")

lines.append("\n## OWASP Top 10\n")
for key, url in URLS.items():
    lines.append(f"- {key} | {url}\n")

lines.append("\n## CWE\n")
for key, url in cwe_URLS.items():
    lines.append(f"- {key} | {url}\n")

lines.append("\n## Framework docs\n")
lines.append(f"- Django Security | {django_url}\n")

lines.append("\n## Style guides\n")
for key, url in style_guides.items():
    lines.append(f"- {key} | {url}\n")

with open("./corpus/sources.md", "w", encoding="utf-8") as f:
    f.writelines(lines)

documents = load_corpus("./corpus/")
print(f"Documente incarcate: {len(documents)}")
build_index(documents, persist_path="vectorstore/")
print("Vectorstore construit.")

# initializeaza memoria episodica goala
client = chromadb.PersistentClient(path="./memory/feedback_index/")
existing = [c.name for c in client.list_collections()]
if "episodic_memory" not in existing:
    client.create_collection("episodic_memory")
