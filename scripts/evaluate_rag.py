import os
import sys
import json
from dotenv import load_dotenv

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
load_dotenv()

import chromadb
from langchain_openai import OpenAIEmbeddings, ChatOpenAI

questions = [
    "Ce este SQL injection si cum se previne?",
    "Care este scorul CVSS pentru Log4Shell?",
    "Ce vulnerabilitati acopera OWASP A03?",
    "Cum se previne XSS in Django?",
    "Ce descrie CWE-89?",
    "Ce este un atac de deserializare nesigura?",
    "Cum se configureaza SSL corect in Django?",
    "Ce este broken access control?",
    "Cum se previne o eroare criptografica?",
    "Ce este authentication bypass si cum se detecteaza?",
]

client = chromadb.PersistentClient(path="../vectorstore/")
collection = client.get_collection("security_corpus")
embeddings = OpenAIEmbeddings(model="text-embedding-3-small")
llm = ChatOpenAI(model="gpt-4o-mini")

results = []
for question in questions:
    vector = embeddings.embed_query(question)
    docs = collection.query(query_embeddings=[vector], n_results=3)
    context = "\n".join(docs["documents"][0])
    prompt = f"Context: {context}\n\nIntrebare: {question}\nRaspuns:"
    answer = llm.invoke(prompt).content

    # scor manual: overlap intre intrebare si raspuns
    q_words = set(question.lower().split())
    a_words = set(answer.lower().split())
    relevancy = round(len(q_words & a_words) / len(q_words), 3)

    results.append({
        "question": question,
        "answer": answer[:200],
        "context_sources": docs["metadatas"][0],
        "relevancy_score": relevancy
    })
    print(f"Q: {question[:50]} | scor: {relevancy}")

avg_score = round(sum(r["relevancy_score"] for r in results) / len(results), 3)
output = {
    "average_relevancy": avg_score,
    "results": results
}

os.makedirs("../logs", exist_ok=True)
with open("../logs/rag_evaluation.json", "w", encoding="utf-8") as f:
    json.dump(output, f, indent=2, ensure_ascii=False)
print(f"\nScor mediu: {avg_score}")
print("Salvat rag_evaluation.json")