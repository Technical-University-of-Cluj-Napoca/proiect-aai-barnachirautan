import os
import sys
import json
import time
import logging
from typing import TypedDict, Optional
from datetime import datetime

# PENTRU A RULA CU python DIN FOLDER U RADACINA
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from langgraph.graph import StateGraph, END
from src.dtos import (
    RepositoryDTO, VulnerabilityDTO, CodeSmellDTO,
    ReviewReportDTO, RetrievalResultDTO, VulnerabilitySeverity,FeedbackDTO, FileReviewDTO, IssueType
)
from src.agents.parser_agent import CodeParserAgent
from src.agents.security_agent import RAGSecurityAgent
from src.agents.quality_agent import CodeQualityAgent
from src.agents.feedback_agent import SelfImprovingFeedbackAgent

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)
MAX_ITER = 3

parser_agent = CodeParserAgent()
security_agent = RAGSecurityAgent()
quality_agent = CodeQualityAgent()
feedback_agent = SelfImprovingFeedbackAgent()

class WorkFlowState(TypedDict):
    repo_url: str
    repository: RepositoryDTO
    context_map: dict[str, list[RetrievalResultDTO]]
    security_map: dict[str, list[VulnerabilityDTO]]
    quality_map: dict[str, list[CodeSmellDTO]]
    feedback_context: dict[str, str]
    critical_alert: bool
    report: ReviewReportDTO
    report_path: str
    iteration: int

def parse_repo(state: WorkFlowState) -> dict:
    start = time.time()
    repo = parser_agent.parse(state["repo_url"])
    logger.info(f"[parse_repo] {len(repo.files)} fisiere in {time.time() - start:.2f}s")
    return {"repository": repo}

# cauta similaritate
def augment_with_memory(state: WorkFlowState) -> dict:
    start = time.time()
    feedback = {}
    for f in state['repository'].files:
        nota = feedback_agent.augment_context(f.content[:500])
        if nota:
            feedback[f.file_path] = nota
    logger.info(f"[augment_with_memory] {len(feedback)} fisiere cu feedback in {time.time() - start:.2f}s")
    return {"feedback_context": feedback}

def security_scan(state: WorkFlowState) -> dict:
    start = time.time()
    # la fiecare iterare dorim sa cautam si mai mult, dupa fiecare iteratie, devine si mai complex,
    # pentru a gasii solutia
    k = 5 + state['iteration'] * 2
    security_map = {}
    for f in state['repository'].files:
        vulns = security_agent.scan(f, k=k)
        security_map[f.file_path] = vulns
    total_vulns = sum(len(v) for v in security_map.values())
    logger.info(f"[security_scan] iteratia {state['iteration']} k={k} → {total_vulns} vulnerabilitati in {time.time() - start:.2f}s")
    return {"security_map": security_map, "iteration": state["iteration"] + 1}


def quality_check(state: WorkFlowState) -> dict:
    start = time.time()
    quality_map = {}
    for f in state["repository"].files:
        dtos, score = quality_agent.evaluate(f)
        quality_map[f.file_path] = dtos
    total_smells = sum(len(v) for v in quality_map.values())
    logger.info(f"[quality_check] {total_smells} code smells in {time.time() - start:.2f}s")
    return {"quality_map": quality_map}

# nu modifica starea, decide_next face decizia
def coverage_check_node(state: WorkFlowState) -> dict:
    return {}


def flag_critical(state : WorkFlowState) -> dict:
    critical = False
    for vuln in state['security_map'].values():
        for v in vuln:
            if v.severity == VulnerabilitySeverity.CRITIC:
                critical = True
    if critical:
        logger.info("ATENTIE: Vulnerabilitate CRITICA detectata!")
    return {"critical_alert": critical}

def decide_next(state : WorkFlowState) -> str:
    total_files = len(state['repository'].files)
    empty = 0
    for vulns in state['security_map'].values():
        for v  in vulns:
            if not vulns or v.coverage_empty:
                empty += 1
    procent = 0.0
    if total_files > 0:
        procent = empty / total_files
    if procent > 0.3 and state["iteration"] < MAX_ITER:
        logger.info(f"Coverage insuficient ({procent:.0%}) - retry iteratia {state['iteration']}")
        return "security_scan" # merge inapoi

    logger.info(f"Coverage ok ({procent:.0%}) - avanseaza")
    return "flag_critical"

def generate_report(state: WorkFlowState) -> dict:
    file_reviews = []
    critical_count = high_count = medium_count = low_count = 0
    for file_path, vulns in state["security_map"].items():
        smells = state["quality_map"].get(file_path, [])
        score = 100.0
        for v in vulns:
            if v.severity == VulnerabilitySeverity.CRITIC:
                critical_count += 1
                score -= 25
            elif v.severity.value == "RIDICAT":
                high_count += 1
                score -= 10
            elif v.severity.value == "MEDIU":
                medium_count += 1
                score -= 5
            else:
                low_count += 1
                score -= 1
        file_reviews.append(FileReviewDTO(
            file_path=file_path,
            vulnerabilities=vulns,
            code_smells=smells,
            quality_score=max(0.0, score)
        ))
    report = ReviewReportDTO(
        repo_url=state["repo_url"],
        repo_name=state["repo_url"].split("/")[-1],
        total_files=len(state["repository"].files),
        reviewed_files=len(file_reviews),
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        file_reviews=file_reviews,
        overall_security_score=max(0.0, 100 - critical_count * 25 - high_count * 10),
        executive_summary=f"Analiza completa: {critical_count} vulnerabilitati critice detectate."
    )
    os.makedirs("logs", exist_ok=True)
    path = f"logs/report_{state['repo_url'].split('/')[-1]}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report.model_dump(), f, indent=2, ensure_ascii=False)

    logger.info(f"Raport salvat: {path}")
    return {"report": report, "report_path": path}


def build_graph():
    graph = StateGraph(WorkFlowState)

    graph.add_node("parse_repo", parse_repo)
    graph.add_node("augmented_memory", augment_with_memory)
    graph.add_node("security_scan", security_scan)
    graph.add_node("quality_check", quality_check)
    graph.add_node("coverage_check_node", coverage_check_node)
    graph.add_node("flag_critical", flag_critical)
    graph.add_node("generate_report", generate_report)

    graph.set_entry_point("parse_repo")
    graph.add_edge("parse_repo", "augmented_memory")
    graph.add_edge("augmented_memory", "security_scan")
    graph.add_edge("security_scan", "quality_check")
    graph.add_edge("quality_check", "coverage_check_node")

    graph.add_conditional_edges(
        "coverage_check_node",
        decide_next,  # decide
        {
            "security_scan": "security_scan",
            "flag_critical": "flag_critical"
        }
    )

    graph.add_edge("flag_critical", "generate_report")
    graph.add_edge("generate_report", END)
    compiled = graph.compile()

    try:
        png = compiled.get_graph().draw_mermaid_png()
        os.makedirs("logs", exist_ok=True)
        with open("logs/workflow_graph.png", "wb") as f:
            f.write(png)
        logger.info("Diagrama exportata: logs/workflow_graph.png")
    except Exception as e:
        logger.warning(f"Nu s-a putut exporta diagrama: {e}")

    return compiled


if __name__ == "__main__":
    app = build_graph()

    # starea initiala
    initial_state = {
        "repo_url": "https://github.com/pallets/click",
        "repository": None,
        "context_map": {},
        "security_map": {},
        "quality_map": {},
        "feedback_context": {},
        "critical_alert": False,
        "report": None,
        "report_path": "",
        "iteration": 0
    }

    result = app.invoke(initial_state)
    print(f"Critical alert: {result['critical_alert']}")
    print(f"Raport salvat: {result['report_path']}")
