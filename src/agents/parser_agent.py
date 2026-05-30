from git import Repo
from pathlib import Path
import sys
import ast
import os
import re
from typing import Tuple
import tomllib
import json
import logging

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from src.dtos import CodeFileDTO, Language, FunctionDTO, RepositoryDTO

logger = logging.getLogger(__name__)

dep_files = ['requirements.txt', 'pyproject.toml', 'package.json']
exclude_dirs = ["node_modules", ".git", "venv", ".venv", "__pycache__", ".idea", ".vscode", "dist", "build"]
exclude_ext = [".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".pdf", ".zip", ".tar", ".gz", ".pyc", ".pyo",
               ".exe", ".dll", ".so", ".lock", ".log"]
language = [".py", ".js", ".ts", ".java", ".go"]

EXT_TO_LANGUAGE = {
    ".py":   Language.PYTHON,
    ".js":   Language.JAVASCRIPT,
    ".ts":   Language.TYPESCRIPT,
    ".java": Language.JAVA,
    ".go":   Language.GO,
}


def is_relevant(path: Path) -> bool:
    for f in path.parts:
        if f in exclude_dirs:
            return False
    if path.name in dep_files:
        return True
    if path.suffix not in language:
        return False
    return True


def browse_dir(folder: Path, relevant: list, dependency: list):
    for f in folder.iterdir():
        if f.is_dir():
            if f.name not in exclude_dirs:
                browse_dir(f, relevant, dependency)
        elif f.is_file() and is_relevant(f):
            if f.name in dep_files:
                dependency.append(f)
            elif f.suffix in language:
                relevant.append(f)


def get_deps_imports(content: str) -> Tuple[list[str], list[str]]:
    imports = []

    for line in content.splitlines():
        line = line.strip()
        search_imp = re.search(r'^import\s+([a-zA-Z0-9_]+)', line)
        if search_imp:
            imports.append(search_imp.group(1))
            continue
        search_dep = re.search(r'^from\s+([a-zA-Z0-9_]+)', line)
        if search_dep:
            imports.append(search_dep.group(1))
            continue

    STDLIB = sys.stdlib_module_names
    imports = list(set(imports))
    dependencies = [m for m in imports if m not in STDLIB]
    return imports, dependencies


def get_functions_python(content: str) -> list[FunctionDTO]:
    functions = []
    try:
        tree = ast.parse(content)
        for n in ast.walk(tree):
            if isinstance(n, ast.FunctionDef):
                functions.append(FunctionDTO(
                    name=n.name,
                    start_line=n.lineno,
                    end_line=n.end_lineno,
                    params=[arg.arg for arg in n.args.args],
                    cyclomatic_complexity=None
                ))
    except SyntaxError:
        pass
    return functions


def get_functions_java(content: str) -> list[FunctionDTO]:
    functions = []
    pattern = r'(?:public|private|protected|static)[\w\s]+\s+(\w+)\s*\(([^)]*)\)'
    for i, line in enumerate(content.splitlines(), 1):
        match = re.search(pattern, line)
        if match:
            name = match.group(1)
            params_str = match.group(2).strip()
            if params_str:
                params = []
                for p in params_str.split(","):
                    p = p.strip()
                    parts = p.split()
                    if parts:
                        params.append(parts[-1])
            else:
                params = []
            functions.append(FunctionDTO(
                name=name,
                start_line=i,
                end_line=i,
                params=params,
                cyclomatic_complexity=None
            ))
    return functions


def get_functions_go(content: str) -> list[FunctionDTO]:
    functions = []
    pattern = r'^func\s+(\w+)\s*\(([^)]*)\)'
    for i, line in enumerate(content.splitlines(), 1):
        match = re.search(pattern, line)
        if match:
            name = match.group(1)
            params_str = match.group(2).strip()
            if params_str:
                params = []
                for p in params_str.split(","):
                    p = p.strip()
                    parts = p.split()
                    if parts:
                        params.append(parts[0])
            else:
                params = []
            functions.append(FunctionDTO(
                name=name,
                start_line=i,
                end_line=i,
                params=params,
                cyclomatic_complexity=None
            ))
    return functions


def get_functions_js(content: str) -> list[FunctionDTO]:
    functions = []
    pattern_func = r'^(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)'
    pattern_arrow = r'^(?:export\s+)?(?:const|let)\s+(\w+)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>'
    pattern_method = r'^\s+(?:async\s+)?(\w+)\s*\(([^)]*)\)\s*\{'
    for i, line in enumerate(content.splitlines(), 1):
        match = (
            re.search(pattern_func, line) or
            re.search(pattern_arrow, line) or
            re.search(pattern_method, line)
        )
        if match:
            name = match.group(1)
            params_str = match.group(2).strip()
            if params_str:
                params = []
                for p in params_str.split(","):
                    p = p.strip()
                    p = p.lstrip(".")
                    p = p.split("=")[0]
                    p = p.split(":")[0]
                    p = p.strip()
                    if p:
                        params.append(p)
            else:
                params = []
            functions.append(FunctionDTO(
                name=name,
                start_line=i,
                end_line=i,
                params=params,
                cyclomatic_complexity=None
            ))
    return functions


def get_functions(content: str, lang: Language) -> list[FunctionDTO]:
    if lang == Language.PYTHON:
        return get_functions_python(content)
    elif lang in (Language.JAVASCRIPT, Language.TYPESCRIPT):
        return get_functions_js(content)
    elif lang == Language.JAVA:
        return get_functions_java(content)
    elif lang == Language.GO:
        return get_functions_go(content)
    return []


def parse_dep_file(path: Path) -> list[str]:
    deps = []
    if path.name == "requirements.txt":
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith('#'):
                dep = re.split(r'[>=<!]', line)[0].strip()
                deps.append(dep)
    elif path.name == "package.json":
        data = json.loads(path.read_text(encoding='utf-8'))
        deps = list(data.get("dependencies", {}).keys())
        deps += list(data.get("devDependencies", {}).keys())
    elif path.name == "pyproject.toml":
        with open(path, "rb") as f:
            data = tomllib.load(f)
        deps = data.get("project", {}).get("dependencies", [])
        if not deps:
            deps = list(data.get("tool", {}).get("poetry", {}).get("dependencies", {}).keys())
    return deps


class CodeParserAgent:

    def parse(self, repo_url: str) -> RepositoryDTO:
        local_path = f"data/repos/{repo_url.split('/')[-1]}"
        if not Path(local_path).exists():
            Repo.clone_from(repo_url, local_path, depth=1)

        repo_depFiles = []
        rel_files = []
        browse_dir(Path(local_path), rel_files, repo_depFiles)

        code_filesDTO = []
        for path in rel_files:
            try:
                ext = EXT_TO_LANGUAGE.get(path.suffix, Language.OTHER)
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                functions = get_functions(content, ext)
                imports, dependencies = get_deps_imports(content)
                dto = CodeFileDTO(
                    file_path=str(path),
                    language=ext,
                    content=content,
                    lines_of_code=len(content.splitlines()),
                    functions=functions,
                    imports=imports,
                    dependencies=dependencies
                )
                code_filesDTO.append(dto)
            except Exception as e:
                logger.warning(f"Fara parsare {path}: {e}")
                continue

        dep_filesDTO = []
        for f in repo_depFiles:
            try:
                dep_filesDTO.extend(parse_dep_file(f))
            except Exception as e:
                logger.warning(f"Fara parsare {f}: {e}")

        return RepositoryDTO(
            url=repo_url,
            name=repo_url.split('/')[-1],
            local_path=local_path,
            files=code_filesDTO,
            total_loc=sum(f.lines_of_code for f in code_filesDTO),
            languages=list(set(f.language for f in code_filesDTO))
        )


if __name__ == "__main__":
    url = sys.argv[1]
    agent = CodeParserAgent()
    result = agent.parse(url)
    print(f"Fisiere: {len(result.files)}")
    print(f"LOC total: {result.total_loc}")