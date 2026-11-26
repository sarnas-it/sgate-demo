"""Тесты правил astpy: контракт проверяется на фикстурах, без SGATE."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import rules  # noqa: E402


def write_tree(files: dict[str, str]) -> str:
    root = tempfile.mkdtemp()
    for name, src in files.items():
        path = Path(root) / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(src, encoding="utf-8")
    return root


def counts(findings: list[rules.Finding]) -> dict[str, int]:
    out: dict[str, int] = {}
    for f in findings:
        out[f.rule] = out.get(f.rule, 0) + 1
    return out


class RouteAuthTest(unittest.TestCase):
    def test_route_without_auth(self):
        root = write_tree({"app/users.py": """
from flask import Flask
app = Flask(__name__)

@app.route("/api/admin/users")
def list_users():
    return []
"""})
        findings, scanned = rules.analyze(root)
        self.assertEqual(scanned, ["app/users.py"])
        self.assertEqual(counts(findings)["sgate-py-route-without-auth"], 1)

    def test_route_with_login_required(self):
        root = write_tree({"app/admin.py": """
from flask_login import login_required

@app.route("/api/admin/users")
@login_required
def list_users():
    return []
"""})
        findings, _ = rules.analyze(root)
        self.assertNotIn("sgate-py-route-without-auth", counts(findings))

    def test_route_with_current_user_in_body(self):
        root = write_tree({"app/users.py": """
@app.get("/api/users")
def list_users():
    if current_user is None:
        return 401
    return []
"""})
        findings, _ = rules.analyze(root)
        self.assertNotIn("sgate-py-route-without-auth", counts(findings))

    def test_public_route_not_flagged(self):
        root = write_tree({"app/health.py": """
@app.get("/health")
def health():
    return "ok"
"""})
        findings, _ = rules.analyze(root)
        self.assertNotIn("sgate-py-route-without-auth", counts(findings))

    def test_plain_function_not_flagged(self):
        root = write_tree({"app/util.py": """
def helper():
    return 1
"""})
        findings, _ = rules.analyze(root)
        self.assertEqual(findings, [])


class IdentityHeaderTest(unittest.TestCase):
    def test_header_without_verification(self):
        root = write_tree({"app/api.py": """
def me(request):
    uid = request.headers.get("X-User-Id")
    return {"id": uid}
"""})
        findings, _ = rules.analyze(root)
        self.assertEqual(counts(findings)["sgate-py-trusted-identity-header"], 1)

    def test_header_with_verification(self):
        root = write_tree({"app/api.py": """
def me(request, token):
    verify_token(token)
    uid = request.headers.get("X-User-Id")
    return {"id": uid}
"""})
        findings, _ = rules.analyze(root)
        self.assertNotIn("sgate-py-trusted-identity-header", counts(findings))

    def test_other_header_not_flagged(self):
        root = write_tree({"app/api.py": """
def trace(request):
    return request.headers.get("X-Request-Id")
"""})
        findings, _ = rules.analyze(root)
        self.assertNotIn("sgate-py-trusted-identity-header", counts(findings))


class SkipsTest(unittest.TestCase):
    def test_skips_vendor_tests_and_tests_dir(self):
        root = write_tree({
            "venv/lib/x.py": '@app.get("/api/admin/x")\ndef f(): pass\n',
            "tests/test_x.py": '@app.get("/api/admin/x")\ndef f(): pass\n',
            "app/real.py": '@app.get("/api/admin/x")\ndef f(): pass\n',
        })
        findings, scanned = rules.analyze(root)
        self.assertEqual(scanned, ["app/real.py"])
        self.assertEqual(len(findings), 1)

    def test_syntax_error_is_skipped(self):
        root = write_tree({"app/broken.py": "def f(:\n"})
        findings, scanned = rules.analyze(root)
        self.assertEqual(findings, [])
        self.assertEqual(scanned, [])


if __name__ == "__main__":
    unittest.main()
