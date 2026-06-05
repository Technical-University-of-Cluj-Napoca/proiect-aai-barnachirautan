import sys
import os
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
# RUN DIN TERMINAL CA SA MEARGA CALEA SI CA SA NU FIE RULAT CA SI FISIER TEST

from src.agents.parser_agent import CodeParserAgent
from src.agents.quality_agent import CodeQualityAgent, generate_distribution

repos = [
    "https://github.com/pallets/flask",
    "https://github.com/nodejs/node-gyp",
]

quality_agent = CodeQualityAgent()
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

    all_dtos = []
    for file_dto in repo_dto.files:
        dtos, score = quality_agent.evaluate(file_dto)
        all_dtos.extend(dtos)
        if dtos:
            print(f"  {file_dto.file_path} | score: {score:.1f} | dtos: {len(dtos)}")
    print(f"\nTotal dtos: {len(all_dtos)}")
    generate_distribution(all_dtos, f"logs/distribution_{url.split('/')[-1]}.png")  # per repo

    with open("./data/review_exemplu.json", "w", encoding="utf-8") as out:
        json.dump(repo_dto.model_dump(), out, indent=2, ensure_ascii=False)
