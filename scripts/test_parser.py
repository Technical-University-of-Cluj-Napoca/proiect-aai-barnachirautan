import sys
import os
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
# RUN DIN TERMINAL CA SA MEARGA CALEA SI CA SA NU FIE RULAT CA SI FISIER TEST

from src.agents.parser_agent import CodeParserAgent

repos = [
    "https://github.com/django/django",
    "https://github.com/WebGoat/WebGoat",
]

for url in repos:
    print(f"\nIncepe testarea pentru: {url}")
    agent = CodeParserAgent()
    repo_dto = agent.parse(url)

    print(f"Fisiere parsate: {len(repo_dto.files)}")
    print(f"Limbaje detectate: {[l.value for l in repo_dto.languages]}")
    print(f"Total functii: {sum(len(f.functions) for f in repo_dto.files)}")
    print(f"Total LOC: {repo_dto.total_loc}")

    print("\nPrimele 3 fisiere:")
    for f in repo_dto.files[:3]:
        print(f"  {f.file_path} | {f.language} | {f.lines_of_code} linii | {len(f.functions)} functii")

    with open("./data/review_exemplu.json", "w", encoding="utf-8") as out:
        json.dump(repo_dto.model_dump(), out, indent=2, ensure_ascii=False)
