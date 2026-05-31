import sys
import os
from typing import Any
import re
from dotenv import load_dotenv
import logging
logger = logging.getLogger(__name__)
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.dtos import CodeFileDTO, VulnerabilityDTO, VulnerabilitySeverity, IssueType
load_dotenv()
import chromadb
from langchain_openai import OpenAIEmbeddings, ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from packaging.version import Version, InvalidVersion


PATTERNS = {
    # A02 - Security Misconfiguration / CWE-16
    "misconfiguration": {
        "keywords": ["DEBUG = True", "ALLOWED_HOSTS = []", "SECRET_KEY =",
                     "CORS_ORIGIN_ALLOW_ALL", "SECURE_SSL_REDIRECT = False"],
        "query": "security misconfiguration debug mode enabled insecure Django settings CWE-16"
    },
    # A04 - Cryptographic Failures / SSL
    "cryptographic": {
        "keywords": ["ssl", "SSL", "verify=False", "check_hostname = False",
                     "CERT_NONE", "md5(", "sha1(", "DES"],
        "query": "cryptographic failure weak SSL TLS certificate verification disabled Python CWE-326"
    },
    # A05 - Injection / CWE-89
    "sql_injection": {
        "keywords": ["execute(", "cursor.", "f\"SELECT", "f'SELECT",
                     "SELECT *", "WHERE", "INSERT INTO", "% s"],
        "query": "SQL injection Python f-string cursor execute user input no sanitization CWE-89 OWASP A03"
    },
    # A07 - Authentication Failures / CWE-287
    "authentication": {
        "keywords": ["password =", "PASSWORD =", "API_KEY =", "token =",
                     "hardcoded", "authenticate(", "login("],
        "query": "hardcoded password API key secret credentials source code authentication CWE-798"
    },
    # A01 - Broken Access Control
    "access_control": {
        "keywords": ["is_admin", "role =", "permission", "ALLOW_ALL",
                     "bypass", "admin = True"],
        "query": "broken access control unauthorized access permission bypass OWASP A01"
    },
    # A03 - Software Supply Chain / dependente
    "dependency": {
        "keywords": ["import django", "import flask", "import requests",
                     "require(", "from django", "from flask"],
        "query": "vulnerable dependency outdated library CVE known vulnerability supply chain OWASP A06"
    },
    # CWE-79 - XSS
    "xss": {
        "keywords": ["innerHTML =", "document.write(", "dangerouslySetInnerHTML",
                     "eval(", "unsafe-inline"],
        "query": "cross site scripting XSS innerHTML user input unsanitized JavaScript CWE-79 OWASP A03"
    },
    # CWE-502 - Deserialization
    "deserialization": {
        "keywords": ["pickle.loads", "yaml.load(", "eval(", "exec(",
                     "marshal.loads", "jsonpickle"],
        "query": "Python pickle.loads unsafe deserialization remote code execution user controlled input CWE-502"
    },
    # Django SSL
    "django_ssl": {
        "keywords": ["SECURE_SSL_REDIRECT", "SESSION_COOKIE_SECURE",
                     "CSRF_COOKIE_SECURE", "SECURE_HSTS"],
        "query": "Django SSL HTTPS configuration insecure cookie security SECURE_SSL_REDIRECT"
    },
    # Django XSS
    "django_xss": {
        "keywords": ["mark_safe(", "safe }}", "autoescape off", "|safe"],
        "query": "Django XSS mark_safe autoescape disabled template injection CWE-79"
    },
    # Style violations
    "style": {
        "keywords": ["        ", "\t", "  =  ", "l = ", "O = "],
        "query": "PEP8 style violation naming convention indentation Python code quality"
    },
}

def construct_query(file : CodeFileDTO) -> list[str]:
    lines = []
    for sub_dict, dict_data in PATTERNS.items():
        if any( word in file.content for word in dict_data["keywords"]):
            lines.append(dict_data["query"])
    return lines

def sendVectorStore(query : str, embeddings : OpenAIEmbeddings, collection, threshold : float = 0.6, k : int = 5) -> list[dict[str, int | Any]]:
    vector = embeddings.embed_query(query)
    docs = collection.query(query_embeddings=[vector], n_results=3)
    #distances = docs['distances'][0] # cat de similar sunt vectorii se calc cu prod scalar, dot = 1 => identici, 0 , perp, adica opusi total
    results = []
    for text, meta, dist in zip(
            docs["documents"][0],
            docs["metadatas"][0],
            docs["distances"][0]
    ):
        score = 1 - dist
        if score >= threshold:
            results.append({
                "text": text,
                "score": score,
                "source": meta["source"],
                "doc_type": meta["doc_type"],
                "cvss_score": meta.get("cvss_score"),
                "owasp_category": meta.get("owasp_category")
            })

    results.sort(key=lambda x: x["score"], reverse=True)
    return results

def manipulate_dependency(deps : list[str], file_path: str, embeddings : OpenAIEmbeddings,
                          collection, threshold : float = 0.6, k : int = 5) -> list[VulnerabilityDTO]:
    vulnerabilities = []
    for d in deps:
        parts = re.split(r'[>=<!]', d)
        name = parts[0].strip()
        if len(parts) > 1:
            version = parts[1].strip()
        else: version = None

        if not version:
            continue
        query = f"{name} vulnerability CVE security"
        chunks = sendVectorStore(query, embeddings, collection, threshold, k)

        for c in chunks:
            if c["doc_type"] == "cve":
                vuln_match = re.search(r'(\d+\.\d+[\.\d]*)', c["text"])
                try:
                    new_version = vuln_match.group(1)
                    if Version(version) < Version(new_version):
                        vulnerabilities.append(VulnerabilityDTO(
                            issue_type=IssueType.DEPENDENCY_RISK,
                            title=f"Dependenta vulnerabila: {name}",
                            description=c["text"][:200],
                            severity=VulnerabilitySeverity.RIDICAT,
                            file_path=file_path,
                            cve_id=c["source"].replace("nvd:", ""),
                            fix_suggestion=f"Actualizeaza {name} la >= {new_version}",
                            cited_source=c["source"],
                            coverage_empty=False
                        ))
                except InvalidVersion:
                    continue
    return vulnerabilities


class RAGSecurityAgent:

    def __init__(self):
        self.client = chromadb.PersistentClient(path="vectorstore/")
        self.collection = self.client.get_collection("security_corpus")
        self.embeddings = OpenAIEmbeddings(model="text-embedding-3-small")
        self.llm = ChatOpenAI(model="gpt-4o-mini")
        self.threshold = 0.3

    def scan(self, file_dto : CodeFileDTO, dep_packages: list[str] = [], k : int = 5) -> list[VulnerabilityDTO]:
        queries = construct_query(file_dto)
        all_chunks = []
        vulnerabilities = []
        for q in queries:
            chunks = sendVectorStore(q, self.embeddings, self.collection, self.threshold, k)
            all_chunks.extend(chunks)
        if not all_chunks:
            return []
        # pana aici i am facut context din bd, cu vectori de informatii

        deps = manipulate_dependency(dep_packages, file_dto.file_path, self.embeddings, self.collection, self.threshold, k)
        vulnerabilities.extend(deps)
        # are acum posibilele probleme

        # asta ii dau sa verifice la llm
        context = "\n".join([c["text"] for c in all_chunks])
        prompt = ChatPromptTemplate.from_template("""
        Esti expert in securitate software. Analizeaza codul de mai jos
        si identifica vulnerabilitatile de securitate.
        Raporteaza strict la contextul furnizat. Nu inventa CVE-uri.

        Corpus de securitate:
        {context}

        Cod analizat ({language}):
        {code}

        Raspunde DOAR in JSON cu aceasta structura, fara text suplimentar:
        [
          {{
            "issue_type": "SECURITY_VULN",
            "title": "titlul vulnerabilitatii",
            "description": "descriere detaliata",
            "severity": "CRITIC",
            "file_path": "{file_path}",
            "line_number": null,
            "affected_snippet": "fragmentul de cod afectat",
            "cve_id": "CVE-YYYY-XXXXX sau null",
            "owasp_category": "A03:2021 sau null",
            "fix_suggestion": "cum se repara concret",
            "cited_source": "sursa din corpus",
            "coverage_empty": false
          }}
        ]
        """)
        chain = prompt | self.llm | JsonOutputParser()
        try:
            result = chain.invoke({
                "context": context,
                "code": file_dto.content[:3000],
                "language": file_dto.language.value,
                "file_path": file_dto.file_path
            })
            for item in result:
                try:
                    vuln = VulnerabilityDTO(
                        id=f"SEC-{len(vulnerabilities):03d}",
                        issue_type=IssueType(item.get("issue_type", "SECURITY_VULN")),
                        title=item.get("title", ""),
                        description=item.get("description", ""),
                        severity=VulnerabilitySeverity(item.get("severity", "MEDIU")),
                        file_path=file_dto.file_path,
                        line_number=item.get("line_number"),
                        affected_snippet=item.get("affected_snippet"),
                        cve_id=item.get("cve_id"),
                        owasp_category=item.get("owasp_category"),
                        fix_suggestion=item.get("fix_suggestion", ""),
                        cited_source=item.get("cited_source", ""),
                        coverage_empty=False
                    )
                    vulnerabilities.append(vuln)
                except Exception as e:
                    logger.warning(f"Nu s-a putut parsa VulnerabilityDTO: {e}")
                    continue
        except Exception as e:
            logger.warning(f"LLM error: {e}")

        return vulnerabilities
