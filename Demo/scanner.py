#!/usr/bin/env python3
import ast
import os
import argparse
from typing import List, Tuple


DANGEROUS_C_FUNCS = {
    "strcpy",
    "sprintf",
    "vsprintf",
    "snprintf",
    "gets",
    "strcat",
    "strncat",
    "memcpy",
    "memmove",
}


def get_func_full_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parts = []
        cur = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))
    return ""


class UnsafeRule:
    def __init__(self, rule_id: str, description: str):
        self.rule_id = rule_id
        self.description = description

    def match(self, call: ast.Call, func_full_name: str) -> bool:
        raise NotImplementedError


class GlobalNameRule(UnsafeRule):
    def __init__(self, names, rule_id, description):
        super().__init__(rule_id, description)
        self.names = set(names)

    def match(self, call: ast.Call, func_full_name: str) -> bool:
        return func_full_name in self.names


class AttrRule(UnsafeRule):
    def __init__(self, targets, rule_id, description):
        super().__init__(rule_id, description)
        self.targets = set(targets)

    def match(self, call: ast.Call, func_full_name: str) -> bool:
        return func_full_name in self.targets


class SubprocessShellRule(UnsafeRule):
    def __init__(self):
        super().__init__("PY-SubprocessShell", "subprocess with shell=True")

    def match(self, call: ast.Call, func_full_name: str) -> bool:
        if not func_full_name.startswith("subprocess."):
            return False
        for kw in call.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant):
                if kw.value.value is True:
                    return True
        return False


class YamlLoadRule(UnsafeRule):
    def __init__(self):
        super().__init__("PY-YamlUnsafeLoad", "yaml.load without SafeLoader")

    def match(self, call: ast.Call, func_full_name: str) -> bool:
        if func_full_name not in {"yaml.load", "ruamel.yaml.load"}:
            return False
        for kw in call.keywords:
            if kw.arg in {"Loader", "loader"}:
                return False
        return True


class PickleLoadRule(UnsafeRule):
    def __init__(self):
        super().__init__("PY-PickleLoad", "pickle.load or pickle.loads")

    def match(self, call: ast.Call, func_full_name: str) -> bool:
        return func_full_name in {"pickle.load", "pickle.loads"}


class JWTRule(UnsafeRule):
    def __init__(self):
        super().__init__("PY-JWT-NoVerify", "jwt.decode without signature verification")

    def match(self, call: ast.Call, func_full_name: str) -> bool:
        if func_full_name.split(".")[-1] != "decode":
            return False
        if not func_full_name.startswith("jwt."):
            return False

        verify_off = False
        options_off = False

        for kw in call.keywords:
            if kw.arg == "verify" and isinstance(kw.value, ast.Constant):
                if kw.value.value is False:
                    verify_off = True
            if kw.arg == "options" and isinstance(kw.value, ast.Dict):
                for k, v in zip(kw.value.keys, kw.value.values):
                    if (
                        isinstance(k, ast.Constant)
                        and k.value == "verify_signature"
                        and isinstance(v, ast.Constant)
                        and v.value is False
                    ):
                        options_off = True

        return verify_off or options_off


class MarshalLoadsRule(UnsafeRule):
    def __init__(self):
        super().__init__("PY-MarshalLoads", "marshal.loads")

    def match(self, call: ast.Call, func_full_name: str) -> bool:
        return func_full_name == "marshal.loads"


class CLikeUnsafeRule(UnsafeRule):
    def __init__(self):
        super().__init__("C-Like-UnsafeFunc", "C-style unsafe function call")

    def match(self, call: ast.Call, func_full_name: str) -> bool:
        last = func_full_name.split(".")[-1]
        return last in DANGEROUS_C_FUNCS


UNSAFE_RULES: List[UnsafeRule] = [
    GlobalNameRule(["eval", "exec"], "PY-EvalExec", "eval or exec"),
    AttrRule(["os.system", "os.popen"], "PY-OS-System", "os.system or os.popen"),
    AttrRule(
        [
            "subprocess.Popen",
            "subprocess.run",
            "subprocess.call",
            "subprocess.check_output",
            "subprocess.check_call",
        ],
        "PY-Subprocess",
        "subprocess command execution",
    ),
    SubprocessShellRule(),
    PickleLoadRule(),
    YamlLoadRule(),
    MarshalLoadsRule(),
    JWTRule(),
    CLikeUnsafeRule(),
]


class SecurityVisitor(ast.NodeVisitor):
    def __init__(self, filename: str, source: str):
        self.filename = filename
        self.source = source
        self.lines = source.splitlines()
        self.results: List[Tuple[int, str, str]] = []

    def visit_Call(self, node: ast.Call):
        func_name = get_func_full_name(node.func)
        if func_name:
            for rule in UNSAFE_RULES:
                if rule.match(node, func_name):
                    code_line = self.lines[node.lineno - 1].rstrip("\n")
                    detail = f"{rule.rule_id}: {rule.description} | {func_name} | {code_line.strip()}"
                    self.results.append((node.lineno, rule.rule_id, detail))
                    break
        self.generic_visit(node)


def scan_file(path: str) -> List[Tuple[int, str, str]]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            src = f.read()
    except Exception:
        return []

    try:
        tree = ast.parse(src, filename=path)
    except SyntaxError:
        return []

    visitor = SecurityVisitor(path, src)
    visitor.visit(tree)
    return visitor.results


def iter_py_files(path: str):
    if os.path.isfile(path):
        if path.endswith(".py"):
            yield path
        return

    for root, _, files in os.walk(path):
        for name in files:
            if name.endswith(".py"):
                yield os.path.join(root, name)


def run_scan(target_path: str):
    any_found = False
    for pyfile in iter_py_files(target_path):
        findings = scan_file(pyfile)
        if not findings:
            continue

        any_found = True
        print(f"\n[+] File: {pyfile}")
        for lineno, rule_id, detail in findings:
            print(f"  L{lineno:<5} {detail}")

    if not any_found:
        print("No unsafe patterns found.")


def main():
    parser = argparse.ArgumentParser(
        description="Scan Python files for unsafe patterns and C-like unsafe functions."
    )
    parser.add_argument("path", nargs="?", help="Path to file or directory")
    args = parser.parse_args()

    if args.path:
        target = args.path
    else:
        target = input("Enter path to scan: ").strip()

    if not target or not os.path.exists(target):
        print("Invalid path.")
        return

    run_scan(target)


if __name__ == "__main__":
    main()
