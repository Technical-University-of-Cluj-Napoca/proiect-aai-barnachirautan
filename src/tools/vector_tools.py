import os
import json

from langchain_openai import OpenAIEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter
import chromadb


def load_corpus(corpus_dir: str) -> list[dict]:
    documents = []

    for root, _, files in os.walk(corpus_dir):
        for file in files:
            path = os.path.join(root, file)

            if "cve" in root:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)

                text = data["cve"]["descriptions"][0]["value"]
                try:
                    cvss = data["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]
                except (KeyError, IndexError):
                    cvss = None

                documents.append({
                    "text": text,
                    "source": f"nvd:{data['cve']['id']}",
                    "doc_type": "cve",
                    "cvss_score": cvss,
                    "owasp_category": None
                })

            elif "owasp" in root:
                with open(path, "r", encoding="utf-8") as f:
                    text = f.read()

                categoria = file.split("_")[0]  # "A01"
                documents.append({
                    "text": text,
                    "source": f"owasp:{file}",
                    "doc_type": "owasp",
                    "cvss_score": None,
                    "owasp_category": categoria
                })

            elif "cwe" in root:
                with open(path, "r", encoding="utf-8") as f:
                    text = f.read()

                documents.append({
                    "text": text,
                    "source": f"cwe:{file}",
                    "doc_type": "cwe",
                    "cvss_score": None,
                    "owasp_category": None
                })

            elif "framework_docs" in root:
                with open(path, "r", encoding="utf-8") as f:
                    text = f.read()

                documents.append({
                    "text": text,
                    "source": f"framework:{file}",
                    "doc_type": "framework_doc",
                    "cvss_score": None,
                    "owasp_category": None
                })

            elif "style_guides" in root:
                with open(path, "r", encoding="utf-8") as f:
                    text = f.read()

                documents.append({
                    "text": text,
                    "source": f"style:{file}",
                    "doc_type": "style_guide",
                    "cvss_score": None,
                    "owasp_category": None
                })

    return documents

def build_index(documents: list[dict], persist_path: str = "vectorstore/"):
    client = chromadb.PersistentClient(path=persist_path)
    existing = [c.name for c in client.list_collections()]
    if "security_corpus" in existing:
        client.delete_collection("security_corpus")
    collection = client.create_collection("security_corpus")

    splitter = RecursiveCharacterTextSplitter(
        chunk_size=400, # am ales 400 ca sa cuprinda si CVSS score si detaliile tehnice impreuna, daca este mult
                        # prea mic va fi scoru cu alte descrieri, prea mare, prea general
        chunk_overlap=60 # cand schimbam contextu sa nu , sa nu pierdem inf de la granita
    )
    embeddings = OpenAIEmbeddings(model="text-embedding-3-small")
    for doc in documents:
        chunks = splitter.split_text(doc["text"])
        for i, chunk in enumerate(chunks):
            vector = embeddings.embed_query(chunk)
            collection.add(
                ids=[f"{doc['source']}_chunk_{i}"],
                embeddings=[vector],
                documents=[chunk],
                metadatas=[{
                    "source": doc["source"],
                    "doc_type": doc["doc_type"],
                    "cvss_score": doc["cvss_score"] or 0.0, # ca sa nu fie none
                    "owasp_category": doc["owasp_category"] or ""
                }]
            )

