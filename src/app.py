import os
import sys

# Schimbam directorul curent la radacina proiectului pentru ca toate
# caile relative (vectorstore/, memory/, data/repos/) sa functioneze corect
ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
os.chdir(ROOT)
sys.path.insert(0, ROOT)

import json
from datetime import datetime

import streamlit as st
from dotenv import load_dotenv

load_dotenv()

# Asigura ca fisierul de stocare a feedbackului exista inainte de orice import
# (SelfImprovingFeedbackAgent il deschide la prima scriere)
def _ensure_memory_store():
    os.makedirs("memory", exist_ok=True)
    path = "memory/feedback_store.json"
    if not os.path.exists(path):
        with open(path, "w", encoding="utf-8") as f:
            json.dump([], f)

_ensure_memory_store()

import src.graph.workflow as _wf
from src.graph.workflow import (
    build_graph,
    WorkFlowState,
    security_agent,
    feedback_agent as _feedback_agent_singleton,
)
from src.dtos import (
    FeedbackDTO,
    FileReviewDTO,
    ReviewReportDTO,
    VulnerabilityDTO,
    VulnerabilitySeverity,
)
from src.agents.feedback_agent import SelfImprovingFeedbackAgent

# ---------------------------------------------------------------------------
# Utilitare UI
# ---------------------------------------------------------------------------

SEVERITY_COLORS = {
    "CRITIC":  "#ffe3e3",
    "RIDICAT": "#fff0e0",
    "MEDIU":   "#fff9c4",
    "SCAZUT":  "#d3f9d8",
    "INFO":    "#d3f9d8",
}

SEVERITY_ORDER = ["CRITIC", "RIDICAT", "MEDIU", "SCAZUT", "INFO"]

NODE_LABELS = {
    "parse_repo":          "Parsare repository...",
    "augmented_memory":    "Recuperare feedback din memorie...",
    "security_scan":       "Scanare securitate...",
    "quality_check":       "Evaluare calitate cod...",
    "coverage_check_node": "Verificare acoperire RAG...",
    "flag_critical":       "Verificare vulnerabilitati critice...",
    "generate_report":     "Generare raport final...",
}


def _worst_severity(review: FileReviewDTO) -> str:
    severities = {v.severity.value for v in review.vulnerabilities}
    for s in SEVERITY_ORDER:
        if s in severities:
            return s
    return "INFO"


def _colored_box(content: str, color: str) -> None:
    st.markdown(
        f'<div style="background-color:{color};padding:8px 12px;'
        f'border-radius:6px;margin-bottom:6px;">{content}</div>',
        unsafe_allow_html=True,
    )


def _generate_markdown(report: ReviewReportDTO) -> str:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M")
    lines = [
        f"# Raport Code Review – {report.repo_name}",
        f"",
        f"**Repository:** {report.repo_url}",
        f"**Data analizei:** {ts}",
        f"**Fisiere:** {report.total_files} totale / {report.reviewed_files} analizate",
        f"**Scor global securitate:** {report.overall_security_score:.1f} / 100",
        f"",
        f"## Rezumat Executiv",
        f"",
        report.executive_summary,
        f"",
        f"## Statistici",
        f"",
        f"| Severitate | Nr. |",
        f"|------------|-----|",
        f"| CRITIC     | {report.critical_count} |",
        f"| RIDICAT    | {report.high_count} |",
        f"| MEDIU      | {report.medium_count} |",
        f"| SCAZUT     | {report.low_count} |",
        f"",
        f"## Detalii per Fisier",
        f"",
    ]
    for fr in report.file_reviews:
        lines += [
            f"### `{fr.file_path}`",
            f"**Scor calitate:** {fr.quality_score:.1f}/100",
            f"",
        ]
        if fr.vulnerabilities:
            lines.append("**Vulnerabilitati:**")
            lines.append("")
            for v in fr.vulnerabilities:
                lines.append(f"#### [{v.severity.value}] {v.title}")
                lines.append(f"")
                lines.append(f"**Descriere:** {v.description}")
                if v.cve_id:
                    lines.append(f"**CVE:** `{v.cve_id}`")
                if v.owasp_category:
                    lines.append(f"**OWASP:** {v.owasp_category}")
                if v.affected_snippet:
                    lines.append(f"**Fragment afectat:**")
                    lines.append(f"```")
                    lines.append(v.affected_snippet)
                    lines.append(f"```")
                lines.append(f"**Sugestie:** {v.fix_suggestion}")
                lines.append(f"**Sursa citata:** {v.cited_source}")
                lines.append(f"")
        if fr.code_smells:
            lines.append("**Code Smells:**")
            for s in fr.code_smells:
                lines.append(f"- `{s.smell_type}` (L{s.line_start}–{s.line_end}): {s.description}")
            lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Pipeline runner
# ---------------------------------------------------------------------------

def _run_pipeline(
    repo_url: str,
    relevance_threshold: float,
    memory_threshold: float,
    use_feedback: bool,
) -> dict:
    """Ruleaza graful LangGraph si afiseaza progresul per fisier in timp real."""

    security_agent.threshold = relevance_threshold
    _feedback_agent_singleton.memory_threshold = memory_threshold

    app = build_graph()

    initial: WorkFlowState = {
        "repo_url": repo_url,
        "repository": None,
        "context_map": {},
        "security_map": {},
        "quality_map": {},
        "feedback_context": {},
        "critical_alert": False,
        "report": None,
        "report_path": "",
        "iteration": 0,
    }

    accumulated = dict(initial)

    with st.status("Analizez repository-ul...", expanded=True) as status:
        # --- bara de progres per fisier ---
        progress_bar  = st.progress(0.0)
        progress_text = st.empty()

        def _update_progress(current: int, total: int, stage: str, filename: str) -> None:
            pct = current / total if total > 0 else 1.0
            progress_bar.progress(pct)
            progress_text.markdown(
                f"**{stage}:** `{filename}` &nbsp;&nbsp; "
                f"**{current} / {total}** fisiere"
            )

        # inregistram callback-ul in modul workflow (acelasi proces, acelasi thread)
        _wf._ui_progress = _update_progress

        try:
            for event in app.stream(initial):
                for node_name, node_output in event.items():
                    label = NODE_LABELS.get(node_name, f"Procesare {node_name}...")

                    if node_name == "parse_repo" and node_output.get("repository"):
                        n = len(node_output["repository"].files)
                        label = f"Parsare completa: {n} fisiere detectate"
                        # resetam bara dupa parsare — urmeaza scanarea
                        progress_bar.progress(0.0)
                        progress_text.empty()

                    if node_name == "security_scan":
                        sec = node_output.get("security_map", {})
                        total_v = sum(len(v) for v in sec.values())
                        label = f"Scanare securitate finalizata: {total_v} vulnerabilitati"

                    status.update(label=label)
                    accumulated.update(node_output)
        finally:
            # curatam callback-ul indiferent de rezultat
            _wf._ui_progress = None

        progress_bar.progress(1.0)
        progress_text.markdown("**Toate fisierele au fost procesate.**")
        status.update(label="Analiza completa!", state="complete")

    return accumulated


# ---------------------------------------------------------------------------
# Sectiunea de feedback per finding
# ---------------------------------------------------------------------------

def _render_feedback_button(vuln: VulnerabilityDTO, file_path: str) -> None:
    key = f"{file_path}::{vuln.id}"
    if key in st.session_state.feedback_submitted:
        st.success("Feedback FP inregistrat.")
        return

    # Fiecare buton are o cheie unica in Streamlit (combinatie id + file_path)
    btn_key = f"fp_{vuln.id}_{hash(file_path)}"
    if st.button("Fals pozitiv", key=btn_key):
        try:
            _ensure_memory_store()
            agent = SelfImprovingFeedbackAgent()
            fb = FeedbackDTO(
                feedback_id=f"FB-{vuln.id}-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                original_finding_id=vuln.id,
                file_path=file_path,
                code_snippet=vuln.affected_snippet or "",
                agent_verdict=vuln.title,
                is_false_positive=True,
                human_comment="Marcat ca fals pozitiv de catre utilizator din UI",
                timestamp=datetime.now().isoformat(),
            )
            agent.store_feedback(fb)
            st.session_state.feedback_submitted.add(key)
            st.rerun()
        except Exception as e:
            st.error(f"Eroare la stocarea feedbackului: {e}")


# ---------------------------------------------------------------------------
# Randare rezultate
# ---------------------------------------------------------------------------

def _render_results(report: ReviewReportDTO, final_state: dict) -> None:
    # Banner CRITIC
    if final_state.get("critical_alert"):
        st.error(
            "ATENTIE: Vulnerabilitate CRITICA detectata. "
            "Revizuiti imediat inainte de deployment."
        )

    # Metrici sumar
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Scor Securitate", f"{report.overall_security_score:.0f}/100")
    c2.metric("CRITIC",  report.critical_count)
    c3.metric("RIDICAT", report.high_count)
    c4.metric("MEDIU",   report.medium_count)
    c5.metric("Fisiere analizate", f"{report.reviewed_files}/{report.total_files}")

    st.divider()
    st.subheader("Fisiere Analizate")

    for fr in report.file_reviews:
        worst = _worst_severity(fr)
        bg = SEVERITY_COLORS[worst]
        n_vuln  = len(fr.vulnerabilities)
        n_smell = len(fr.code_smells)
        title = (
            f"{os.path.basename(fr.file_path)} | "
            f"Scor: {fr.quality_score:.0f}/100 | "
            f"Vulnerabilitati: {n_vuln} | "
            f"Code smells: {n_smell}"
        )

        with st.expander(title, expanded=(worst == "CRITIC")):
            _colored_box(
                f"<strong>Severitate maxima:</strong> {worst} &nbsp;|&nbsp; "
                f"<strong>Cale:</strong> <code>{fr.file_path}</code>",
                bg,
            )

            # --- Vulnerabilitati ---
            if fr.vulnerabilities:
                st.markdown("**Vulnerabilitati de Securitate**")
                for v in fr.vulnerabilities:
                    v_color = SEVERITY_COLORS.get(v.severity.value, "#fff")
                    meta = ""
                    if v.cve_id:
                        meta += f"<strong>CVE:</strong> {v.cve_id} &nbsp; "
                    if v.owasp_category:
                        meta += f"<strong>OWASP:</strong> {v.owasp_category}"
                    _colored_box(
                        f"<strong>[{v.severity.value}] {v.title}</strong><br>"
                        f"{v.description}<br>{meta}",
                        v_color,
                    )
                    if v.affected_snippet:
                        st.code(v.affected_snippet, language="python")
                    st.markdown(f"**Sugestie:** {v.fix_suggestion}")
                    st.caption(f"Sursa citata: {v.cited_source}")

                    # Buton de feedback per finding
                    _render_feedback_button(v, fr.file_path)
                    st.divider()
            else:
                st.success("Nicio vulnerabilitate detectata in acest fisier.")

            # --- Code smells ---
            if fr.code_smells:
                with st.expander(f"Code Smells ({n_smell})", expanded=False):
                    for s in fr.code_smells:
                        st.markdown(
                            f"- **{s.smell_type}** "
                            f"(L{s.line_start}–{s.line_end}): {s.description}"
                        )

    # --- Download raport ---
    st.divider()
    st.subheader("Export Raport")
    md = _generate_markdown(report)
    st.download_button(
        label="Descarca Raport Markdown",
        data=md,
        file_name=f"security_report_{report.repo_name}_{datetime.now().strftime('%Y%m%d')}.md",
        mime="text/markdown",
        type="primary",
    )
    with st.expander("Preview Raport Markdown"):
        st.markdown(md)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    st.set_page_config(
        page_title="Code Review & Security Scan",
        page_icon="🔒",
        layout="wide",
    )
    st.title("Code Review & Security Vulnerability Detector")
    st.markdown(
        "Sistem multi-agent pentru analiza codului sursa si detectia "
        "vulnerabilitatilor de securitate bazat pe RAG + LangGraph."
    )

    # --- Initializare session state ---
    if "report"             not in st.session_state:
        st.session_state.report = None
    if "final_state"        not in st.session_state:
        st.session_state.final_state = None
    if "feedback_submitted" not in st.session_state:
        st.session_state.feedback_submitted = set()

    # --- Sidebar ---
    with st.sidebar:
        st.header("Configurare Analiza")

        repo_url = st.text_input(
            "URL Repository GitHub",
            placeholder="https://github.com/user/repo",
            help="Repository public sau privat (cu GITHUB_TOKEN in .env)",
        )
        analyze_btn = st.button(
            "Analizeaza Repository", type="primary", use_container_width=True
        )

        st.divider()
        st.subheader("Praguri RAG")
        relevance_threshold = st.slider(
            "Prag relevanta",
            min_value=0.0, max_value=1.0, value=0.3, step=0.05,
            help="Chunk-urile cu scor sub acest prag sunt ignorate de Security Agent",
        )
        memory_threshold = st.slider(
            "Prag memorie episodica",
            min_value=0.0, max_value=1.0, value=0.75, step=0.05,
            help="Feedbackuri cu similaritate sub acest prag nu sunt recuperate",
        )
        use_feedback = st.checkbox(
            "Activeaza agentul de feedback",
            value=True,
            help="Feedback-ul stocat anterior imbunatateste review-urile viitoare",
        )

        st.divider()
        if st.button("Reset memorie episodica", type="secondary"):
            try:
                _ensure_memory_store()
                SelfImprovingFeedbackAgent().reset_memory()
                st.success("Memoria episodica a fost resetata!")
            except Exception as e:
                st.error(f"Eroare reset: {e}")

    # --- Declansare pipeline ---
    if analyze_btn and repo_url:
        # Resetam starea anterioara
        st.session_state.report = None
        st.session_state.final_state = None
        st.session_state.feedback_submitted = set()

        try:
            final_state = _run_pipeline(
                repo_url, relevance_threshold, memory_threshold, use_feedback,
            )
            st.session_state.final_state = final_state
            st.session_state.report = final_state.get("report")
        except Exception as e:
            import traceback
            st.error(f"Eroare la analiza: {e}")
            st.code(traceback.format_exc())

    # --- Afisare rezultate ---
    if st.session_state.report:
        _render_results(st.session_state.report, st.session_state.final_state or {})
    else:
        st.info(
            "Introdu URL-ul unui repository GitHub si apasa "
            "'Analizeaza Repository' pentru a incepe."
        )


if __name__ == "__main__":
    main()
