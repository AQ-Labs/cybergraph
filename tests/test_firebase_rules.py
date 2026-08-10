from __future__ import annotations

from pathlib import Path

from cybergraph.analysis.firebase_rules import analyze_firebase_rules_file

OPEN = """rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /users/{uid} {
      allow read, write: if true;
    }
  }
}
"""

GUARDED = """rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /users/{uid} {
      allow read, write: if request.auth != null;
    }
  }
}
"""


def _write(tmp_path: Path, name: str, text: str) -> Path:
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


def test_open_rule_is_flagged(tmp_path: Path) -> None:
    p = _write(tmp_path, "firestore.rules", OPEN)
    nodes, _edges, findings = analyze_firebase_rules_file(p, tmp_path)
    assert any(n.kind == "File" for n in nodes)
    assert [f.rule_id for f in findings] == ["CG-FIREBASE-RULES-OPEN"]
    f = findings[0]
    assert f.cwe == "CWE-732"
    assert "if true" in f.evidence


def test_guarded_rule_is_clean(tmp_path: Path) -> None:
    p = _write(tmp_path, "firestore.rules", GUARDED)
    nodes, _edges, findings = analyze_firebase_rules_file(p, tmp_path)
    assert findings == []
    assert any(n.kind == "File" for n in nodes)


def test_inline_suppression_respected(tmp_path: Path) -> None:
    text = OPEN.replace("if true;", "if true; // cybergraph: ignore CG-FIREBASE-RULES-OPEN")
    p = _write(tmp_path, "firestore.rules", text)
    _nodes, _edges, findings = analyze_firebase_rules_file(p, tmp_path)
    assert findings == []
