import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from src.dtos import CodeFileDTO, Language, FunctionDTO, RepositoryDTO, CodeSmellDTO
import radon.complexity as rc
import re
import vulture
from difflib import SequenceMatcher
import ast

def detect_highComplexity(context : str, file_path: str) -> list[CodeSmellDTO]:
    dtos = []
    try:
        results = rc.cc_visit(context)   # contine nume, complexitate(nr), linie start si finish
    except Exception:
        return []
    for r in results:
        if r.complexity > 10:
            dtos.append(CodeSmellDTO(
                smell_type= 'HIGH_COMPLEXITY',
                description=f"Functia '{r.name}' are complexitate ciclomatica {r.complexity} (prag: 10)",
                file_path= file_path,
                line_start = r.lineno,
                line_end= r.endline,
                cyclomatic_complexity=float(r.complexity),
                fix_suggestion= "Sparge functia in functii mai mici cu o singura responsabilitate"
            ))
    return dtos

def detect_longMethod(context : str, file_path: str) -> list[CodeSmellDTO]:
    dtos = []
    try:
        results = rc.cc_visit(context)   # contine nume, complexitate(nr), linie start si finish
    except Exception:
        return []
    for r in results:
        length = r.endline - r.lineno + 1
        if length > 50:
            dtos.append(CodeSmellDTO(
                smell_type="LONG_METHOD",
                description=f"Functia '{r.name}' are {length} linii (peste 50)",
                file_path=file_path,
                line_start=r.lineno,
                line_end=r.endline,
                cyclomatic_complexity=None,
                fix_suggestion="Sparge functia in functii mai mici cu o singura responsabilitate"
            ))
    return dtos

def detect_magicNumbers(context : str, file_path: str) -> list[CodeSmellDTO]:
    dtos = []
    for i, line in enumerate(context.splitlines(), 1):
        line_s = line.strip()
        if line_s.startswith('#'):
            continue
        if re.match(r'^[A-Za-z_][A-Za-z0-9_]*\s*=\s*\d+', line_s): # constante definite si cu cifre, asta e bine sa fie
            continue

        #excludem cifrele 0 si 1
        matches = re.findall(r'\b([2-9]\d*|\d{2,})\b', line_s)
        for m in matches:
            dtos.append(CodeSmellDTO(
                smell_type="MAGIC_NUMBERS",
                description=f"Numar magic '{m}' la linia {i}",
                file_path=file_path,
                line_start=i,
                line_end=i,
                cyclomatic_complexity=None,
                fix_suggestion=f"Defineste o constanta cu nume descriptiv in loc de {m}"
            ))
    return dtos

def detect_deadCode(file_path: str) -> list[CodeSmellDTO]:
    dtos = []
    try:
        v = vulture.Vulture()
        v.scavenge(file_path)
        for item in v.get_unused_code():
            if item.confidence >= 80:
                dtos.append(CodeSmellDTO(
                    smell_type="DEAD_CODE",
                    description=f"'{item.name}' definit dar nefolosit ({item.typ})",
                    file_path=file_path,
                    line_start=item.first_lineno,
                    line_end=item.first_lineno,
                    cyclomatic_complexity=None,
                    fix_suggestion=f"Sterge '{item.name}' daca nu e folosit nicaieri"
                ))
    except Exception:
        return []

    return dtos

def detect_DuplicateCode(content: str, file_path: str, functions: list) -> list[CodeSmellDTO]:
    dtos = []
    lines = content.splitlines()

    f_text = []
    for f in functions:
        func_code = "\n".join(lines[f.start_line - 1:f.end_line])
        f_text.append((f.name, func_code, f.start_line, f.end_line))

    for i in range(len(f_text)):
        for j in range(i + 1, len(f_text)):
            name1, code1, start1, end1 = f_text[i]
            name2, code2, start2, end2 = f_text[j]
            similar = SequenceMatcher(None, code1, code2).ratio()
            if similar > 0.80:
                dtos.append(CodeSmellDTO(
                    smell_type="DUPLICATE_CODE",
                    description=f"'{name1}' si '{name2}' sunt {int(similar * 100)}% similare",
                    file_path=file_path,
                    line_start=start1,
                    line_end=end1,
                    cyclomatic_complexity=None,
                    fix_suggestion=f"Extrage logica comuna intr-o functie separata"
                ))
    return dtos

def detect_godClass(content: str, file_path: str) -> list[CodeSmellDTO]:
    dtos = []
    try:
        tree = ast.parse(content)
    except Exception:
        return []
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            lines = node.end_lineno - node.lineno
            public = [
                n for n in node.body
                if isinstance(n, ast.FunctionDef)
                   and not n.name.startswith("_")
            ]
            if len(public) > 10 and lines > 200:
                dtos.append(CodeSmellDTO(
                    smell_type="GOD_CLASS",
                    description=f"Clasa '{node.name}' are {len(public)} metode publice si {lines} linii",
                    file_path=file_path,
                    line_start=node.lineno,
                    line_end=node.end_lineno,
                    cyclomatic_complexity=None,
                    fix_suggestion=f"Sparge clasa '{node.name}' in clase mai mici cu o singura responsabilitate"
                ))


    return dtos


class CodeQualityAgent:
    def evaluate(file_dto) -> list[CodeSmellDTO]:
        dtos = []

        return dtos