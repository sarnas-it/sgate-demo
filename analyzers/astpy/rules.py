"""AST-правила для Python — второй модуль SGATE на другом языке.

Контракт тот же, что у Go-модуля: SGATE_REPO/SGATE_OUT → SARIF, прогресс
«py-ast-scanned: <файл>». Пакет не знает про SGATE, поэтому ядро и
analyzers.yaml не меняются при замене языка.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

ROUTE_METHODS = {"route", "get", "post", "put", "delete", "patch", "api_route"}

# Пути, которые по смыслу публичные: их отсутствие auth — норма, а не находка.
PUBLIC_PATHS = {
    "/", "/health", "/healthz", "/ready", "/readyz", "/livez",
    "/ping", "/metrics", "/docs", "/redoc", "/openapi.json", "/favicon.ico",
}

AUTH_MARKERS = (
    "login_required", "jwt_required", "auth_required", "requires_auth",
    "permission_required", "token_required", "verify_token", "verify_jwt",
    "current_user", "get_current_user", "current_active_user", "authorize",
    "check_permission", "require_permission",
)

IDENTITY_HEADERS = {
    "x-user-id", "x-user-email", "x-user-roles", "x-user-permissions",
}

VERIFY_MARKERS = ("verify", "decode", "validate", "jwt", "signature", "hmac")

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
    "env", "site-packages", "testdata", ".mypy_cache", ".pytest_cache",
    "dist", "build", ".tox",
}


@dataclass
class Finding:
    rule: str
    severity: str
    message: str
    file: str
    line: int
    column: int


def catalog() -> list[dict]:
    return [
        {
            "id": "sgate-py-route-without-auth",
            "severity": "MEDIUM",
            "cwe": "CWE-862",
            "message": "Маршрут зарегистрирован без проверки аутентификации или прав.",
        },
        {
            "id": "sgate-py-trusted-identity-header",
            "severity": "MEDIUM",
            "cwe": "CWE-290",
            "message": "Identity-заголовок читается без проверки подписи/токена.",
        },
    ]


def analyze(root: str) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    scanned: list[str] = []
    for path in _walk_python(Path(root)):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError as exc:
            # Битый файл не должен превращать прогон в ложный ноль.
            print(f"py-ast-skip: {path}: {exc}", flush=True)
            continue
        rel = str(path.relative_to(root))
        scanned.append(rel)
        findings.extend(_check_routes(tree, rel))
        findings.extend(_check_identity_headers(tree, rel))
    return findings, scanned


def _walk_python(root: Path):
    for path in sorted(root.rglob("*.py")):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        name = path.name
        if name.startswith("test_") or name.endswith("_test.py") or name == "conftest.py":
            continue
        yield path


def _decorator_name(dec: ast.expr) -> str:
    node = dec.func if isinstance(dec, ast.Call) else dec
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _route_path(dec: ast.expr) -> str | None:
    if isinstance(dec, ast.Call) and dec.args:
        first = dec.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            return first.value
    return None


def _names_in(node: ast.AST) -> set[str]:
    out: set[str] = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Name):
            out.add(n.id.lower())
        elif isinstance(n, ast.Attribute):
            out.add(n.attr.lower())
    return out


def _has_any(names: set[str], markers: tuple[str, ...]) -> bool:
    for name in names:
        for marker in markers:
            if marker in name:
                return True
    return False


def _function_has_auth(fn: ast.AST) -> bool:
    names: set[str] = set()
    for dec in getattr(fn, "decorator_list", []):
        names |= _names_in(dec)
    names |= _names_in(fn)
    return _has_any(names, AUTH_MARKERS)


def _check_routes(tree: ast.AST, rel: str) -> list[Finding]:
    out: list[Finding] = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        route = None
        for dec in fn.decorator_list:
            if _decorator_name(dec).lower() in ROUTE_METHODS:
                route = dec
                break
        if route is None:
            continue
        path = _route_path(route)
        if path in PUBLIC_PATHS:
            continue
        if _function_has_auth(fn):
            continue
        out.append(Finding(
            rule="sgate-py-route-without-auth",
            severity="MEDIUM",
            message=f"маршрут {fn.name} ({path or 'без литерального пути'}) без проверки аутентификации/прав",
            file=rel,
            line=fn.lineno,
            column=fn.col_offset + 1,
        ))
    return out


def _check_identity_headers(tree: ast.AST, rel: str) -> list[Finding]:
    out: list[Finding] = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        names = _names_in(fn)
        if _has_any(names, VERIFY_MARKERS):
            continue
        seen: set[int] = set()
        for node in ast.walk(fn):
            key = _identity_key(node)
            if key is None:
                continue
            line = getattr(node, "lineno", fn.lineno)
            if line in seen:
                continue
            seen.add(line)
            out.append(Finding(
                rule="sgate-py-trusted-identity-header",
                severity="MEDIUM",
                message=f"identity-заголовок {key} читается без проверки подписи/токена",
                file=rel,
                line=line,
                column=getattr(node, "col_offset", 0) + 1,
            ))
    return out


def _identity_key(node: ast.AST) -> str | None:
    value = None
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in {"get", "pop"}:
        if node.args and isinstance(node.args[0], ast.Constant):
            value = node.args[0].value
    elif isinstance(node, ast.Subscript):
        slice_node = node.slice
        if isinstance(slice_node, ast.Constant):
            value = slice_node.value
    if isinstance(value, str) and value.lower() in IDENTITY_HEADERS:
        return value.lower()
    return None
