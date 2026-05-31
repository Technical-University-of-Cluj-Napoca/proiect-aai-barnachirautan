from enum import Enum
from typing import Optional
from pydantic import BaseModel


class VulnerabilitySeverity(str, Enum):
    CRITIC  = "CRITIC"
    RIDICAT = "RIDICAT"
    MEDIU   = "MEDIU"
    SCAZUT  = "SCAZUT"
    INFO    = "INFO"

class IssueType(str, Enum):
    SECURITY_VULN    = "SECURITY_VULN"
    CODE_SMELL       = "CODE_SMELL"
    STYLE_VIOLATION  = "STYLE_VIOLATION"
    DEPENDENCY_RISK  = "DEPENDENCY_RISK"
    LOGIC_ERROR      = "LOGIC_ERROR"
    HARDCODED_SECRET = "HARDCODED_SECRET"

class Language(str, Enum):
    PYTHON     = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA       = "java"
    GO         = "go"
    OTHER      = "other"

class FunctionDTO(BaseModel):
    name: str
    start_line: int
    end_line: int
    params: list[str]
    cyclomatic_complexity: Optional[float] = None

class CodeFileDTO(BaseModel):
    file_path: str
    language: Language
    content: str
    lines_of_code: int
    functions: list[FunctionDTO]
    imports: list[str]
    dependencies: list[str]

class RepositoryDTO(BaseModel):
    url: str
    name: str
    local_path: str
    files: list[CodeFileDTO]
    total_loc: int
    languages: list[Language]
    dep_packages: list[str] # sa am pt verificarea versiunilor

class VulnerabilityDTO(BaseModel):
    id: str
    issue_type: IssueType
    title: str
    description: str
    severity: VulnerabilitySeverity
    file_path: str
    line_number: Optional[int]
    affected_snippet: Optional[str]
    cve_id: Optional[str]
    owasp_category: Optional[str]
    fix_suggestion: str
    cited_source: str
    coverage_empty: bool

class CodeSmellDTO(BaseModel):
    smell_type: str
    description: str
    file_path: str
    line_start: int
    line_end: int
    cyclomatic_complexity: Optional[float]
    fix_suggestion: str

class DependencyRiskDTO(BaseModel):
    package_name: str
    installed_version: str
    vulnerable_versions: list[str]
    cve_id: str
    cvss_score: float

class RetrievalResultDTO(BaseModel):
    text: str
    source: str
    score: float
    doc_type: str
    cvss_score: Optional[float]

class FileReviewDTO(BaseModel):
    file_path: str
    vulnerabilities: list[VulnerabilityDTO]
    code_smells: list[CodeSmellDTO]
    quality_score: float

class FeedbackDTO(BaseModel):
    feedback_id: str
    original_finding_id: str
    file_path: str
    code_snippet: str
    agent_verdict: str
    is_false_positive: bool
    human_comment: str
    timestamp: str

class ReviewReportDTO(BaseModel):
    repo_url: str
    repo_name: str
    total_files: int
    reviewed_files: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    file_reviews: list[FileReviewDTO]
    overall_security_score: float
    executive_summary: str

