import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from src.dtos import CodeFileDTO, Language, FunctionDTO, RepositoryDTO, CodeSmellDTO
import radon.complexity as rc
import re
import vulture
from difflib import SequenceMatcher
import ast
import pycodestyle
from collections import defaultdict
import subprocess
import json
import matplotlib.pyplot as plt
from collections import Counter

# SA AI NODE JS INSTALAT PENTRU npm install -g eslint

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
        HTTP_CODES = {"200", "201", "204", "301", "302", "400", "401", "403", "404", "500"}
        for m in matches:
            if m not in HTTP_CODES:
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
        v.scavenge([file_path])
        for item in v.get_unused_code():
            if item.confidence >= 80:
                dtos.append(CodeSmellDTO(
                    smell_type="DEAD_CODE",
                    description=f"'{item.name}' definit, dar nefolosit ({item.typ})",
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

def detect_stylePython(content: str, file_path: str) -> list[CodeSmellDTO]:
    dtos = []
    errors_by_category = defaultdict(int)

    class Counter(pycodestyle.StandardReport):
        def error(self, line_number, offset, text, check):
            code = text[:4] # primele 4 sunt tipu de erorare
            errors_by_category[code] +=1
            return super().error(line_number, offset, text, check)

    style = pycodestyle.StyleGuide(quiet=True, reporter=Counter)
    style.check_files([file_path])
    for code, count in errors_by_category.items():
        dtos.append(CodeSmellDTO(
            smell_type="STYLE_VIOLATION",
            description=f"Violari PEP8 categorie {code}: {count} aparitii",
            file_path=file_path,
            line_start=1,
            line_end=1,
            cyclomatic_complexity=None,
            fix_suggestion="Ruleaza autopep8 pentru fix automat",
            count=count
        ))
    return dtos

def detect_styleJsTs(content: str, file_path: str) -> list[CodeSmellDTO]:
    dtos = []
    try:
        result = subprocess.run(
            ["eslint", "--format", "json", file_path],
            capture_output=True,
            text = True
        )# pentru a detecta textu in js/ts, asa functioneaza eslint ca e in nodeJS
        data = json.loads(result.stdout)
        errors_by_category = defaultdict(int)
        for f in data:
            for msg in f.get("messages", []):
                rule = msg.get("ruleId", "unknown")
                errors_by_category[rule] +=1

        for rule, i in errors_by_category.items():
            dtos.append(CodeSmellDTO(
                smell_type="STYLE_VIOLATION",
                description=f"Violari ESLint regula '{rule}': {i} aparitii",
                file_path=file_path,
                line_start=1,
                line_end=1,
                cyclomatic_complexity=None,
                fix_suggestion="Ruleaza eslint --fix pentru fix automat",
                count=i
            ))
    except Exception:
        return []
    return dtos



class CodeQualityAgent:
    def evaluate(self, file_dto:CodeFileDTO) -> tuple[list[CodeSmellDTO], float]:
        dtos = []
        file_path = file_dto.file_path
        content = file_dto.content
        if file_dto.language == Language.PYTHON:
            dtos.extend(detect_highComplexity(content, file_path))
            dtos.extend(detect_longMethod(content, file_path))
            dtos.extend(detect_magicNumbers(content, file_path))
            dtos.extend(detect_deadCode(file_path))
            dtos.extend(detect_DuplicateCode(content, file_path, file_dto.functions))
            dtos.extend(detect_godClass(content, file_path))
            dtos.extend(detect_stylePython(content, file_path))
        elif file_dto.language in (Language.JAVASCRIPT, Language.TYPESCRIPT):
            dtos.extend(detect_longMethod(content, file_path))
            dtos.extend(detect_magicNumbers(content, file_path))
            dtos.extend(detect_DuplicateCode(content, file_path, file_dto.functions))
            dtos.extend(detect_styleJsTs(content, file_path))

        score = 100
        for s in dtos:
            if s.smell_type in ("GOD_CLASS", "HIGH_COMPLEXITY"):
                score -= 25  # CRITIC
            elif s.smell_type in ("LONG_METHOD", "DUPLICATE_CODE", "DEAD_CODE"):
                score -= 10  # HIGH, se pot ascunde f usor probleme de securitate
            elif s.smell_type == "MAGIC_NUMBERS":
                score -= 5  # MED, poate dar f rar, la comparatii
            elif s.smell_type == "STYLE_VIOLATION":
                score -= 1  # LOW, nu afecteaza securitatea, fff rar

        quality_score = max(0.0, min(100.0, float(score)))
        return dtos, quality_score


def generate_distribution(all_smells: list[CodeSmellDTO], output_path: str = "logs/vulnerability_distribution.png"):
    # numara fiecare tip de smell
    counts = Counter(s.smell_type for s in all_smells)

    if not counts:
        return

    # separa securitate vs calitate
    security = ["HIGH_COMPLEXITY", "GOD_CLASS", "DEAD_CODE", "DUPLICATE_CODE"]
    quality = ["LONG_METHOD", "MAGIC_NUMBERS", "STYLE_VIOLATION"]

    labels = list(counts.keys())
    values = list(counts.values())
    colors = [
        "red" if l in security else "steelblue"
        for l in labels
    ]

    plt.figure(figsize=(10, 6))
    bars = plt.bar(labels, values, color=colors)
    plt.title("Distributia tipurilor de probleme (rosu=securitate, albastru=calitate)")
    plt.xlabel("Tip problema")
    plt.ylabel("Numar aparitii")
    plt.xticks(rotation=45, ha="right")
    for bar, val in zip(bars, values):
        plt.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.1,
                 str(val), ha="center", va="bottom")

    os.makedirs("logs", exist_ok=True)
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()
    print(f"Salvat {output_path}")