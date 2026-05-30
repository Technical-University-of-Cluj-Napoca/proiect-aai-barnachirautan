import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.agents.security_agent import RAGSecurityAgent, sendVectorStore
from src.dtos import CodeFileDTO, Language
import matplotlib.pyplot as plt
import numpy as np
from src.agents.security_agent import construct_query

agent = RAGSecurityAgent()

FRAGMENTS = {
    "sql_injection": """
def get_user(uid):
    query = f"SELECT * FROM users WHERE id={uid}"
    cursor.execute(query)
""",
    "hardcoded_secret": """
API_KEY = "sk-abc123secretkey"
PASSWORD = "admin123"
""",
    "dependency": """
import django
import requests
from flask import Flask
""",
    "deserialization": """
import pickle
data = pickle.loads(user_input)
""",
    "misconfiguration": """
DEBUG = True
ALLOWED_HOSTS = []
SECRET_KEY = "hardcoded-secret"
"""
}

scores_matrix = []
labels_y = list(FRAGMENTS.keys())
labels_x = [f"chunk_{i}" for i in range(5)]

for frag_name, code in FRAGMENTS.items():
    file_dto = CodeFileDTO(
        file_path=f"test/{frag_name}.py",
        language=Language.PYTHON,
        content=code,
        lines_of_code=len(code.splitlines()),
        functions=[],
        imports=[],
        dependencies=[]
    )
    queries = construct_query(file_dto)

    if queries:
        chunks = sendVectorStore(queries[0], agent.embeddings, agent.collection, threshold=0.0, k=5)
        row = [c["score"] for c in chunks]
        # completeaza cu 0 daca mai putin de 5 chunks
        while len(row) < 5:
            row.append(0.0)
        scores_matrix.append(row[:5])
    else:
        scores_matrix.append([0.0] * 5)

    print(f"\n{frag_name}:")
    vulns = agent.scan(file_dto)
    for v in vulns:
        print(f"  [{v.severity}] {v.title}")

# heatmap 5x5
fig, ax = plt.subplots(figsize=(8, 6))
im = ax.imshow(scores_matrix, cmap="YlOrRd", vmin=0, vmax=1)
plt.colorbar(im)
ax.set_xticks(range(5))
ax.set_yticks(range(5))
ax.set_xticklabels(labels_x, rotation=45)
ax.set_yticklabels(labels_y)
ax.set_title("Retrieval Heatmap 5x5")

for i in range(5):
    for j in range(5):
        ax.text(j, i, f"{scores_matrix[i][j]:.2f}", ha="center", va="center", fontsize=8)

os.makedirs("logs", exist_ok=True)
plt.tight_layout()
plt.savefig("logs/retrieval_heatmap.png")
