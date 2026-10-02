"""Tests for scripts/generate_decision_explorer.py: the static-HTML
decision explorer must actually render real certificates and correctly
report chain linkage, for both its input paths (locally-generated demo
chain, and an externally-supplied certificate list such as a service
export)."""

from __future__ import annotations

import importlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import generate_decision_explorer as explorer  # noqa: E402


def _extract_certs(html: str) -> list[dict]:
    m = re.search(r"const CERTS = (\[.*?\]);", html, re.DOTALL)
    assert m, "decision explorer HTML must embed a CERTS JSON array"
    return json.loads(m.group(1))


def test_demo_chain_generates_real_verdicts_across_all_three_outcomes():
    certs, chain_intact = explorer.generate_demo_chain()
    assert chain_intact is True
    verdicts = {c["verdict"] for c in certs}
    assert verdicts == {"ADMIT", "HOLD", "BLOCK"}
    assert len(certs) >= 7


def test_demo_chain_certificate_hashes_actually_link():
    certs, _ = explorer.generate_demo_chain()
    prev = "0" * 64
    for c in certs:
        assert c["prev_hash"] == prev
        prev = c["certificate_hash"]


def test_render_html_embeds_the_real_certificate_data():
    certs, chain_intact = explorer.generate_demo_chain()
    html = explorer.render_html(certs, chain_intact)
    embedded = _extract_certs(html)
    assert [c["incident_id"] for c in embedded] == [c["incident_id"] for c in certs]
    assert "intact" in html
    assert "BROKEN" not in html


def test_render_html_flags_a_broken_chain_honestly():
    certs, _ = explorer.generate_demo_chain()
    html = explorer.render_html(certs, chain_intact=False)
    assert "BROKEN" in html


def test_load_certificates_detects_intact_linkage(tmp_path):
    certs, _ = explorer.generate_demo_chain()
    path = tmp_path / "certs.json"
    path.write_text(json.dumps(certs))
    loaded, chain_intact = explorer.load_certificates(str(path))
    assert chain_intact is True
    assert len(loaded) == len(certs)


def test_load_certificates_detects_a_broken_chain(tmp_path):
    certs, _ = explorer.generate_demo_chain()
    tampered = list(certs)
    tampered[-1] = {**tampered[-1], "prev_hash": "f" * 64}  # sever the link
    path = tmp_path / "certs.json"
    path.write_text(json.dumps(tampered))
    _, chain_intact = explorer.load_certificates(str(path))
    assert chain_intact is False


def test_main_writes_a_valid_html_file(tmp_path):
    out = tmp_path / "report.html"
    sys.argv = ["generate_decision_explorer.py", "--output", str(out)]
    explorer.main()
    assert out.exists()
    html = out.read_text()
    assert "<!doctype html>" in html.lower()
    certs = _extract_certs(html)
    assert len(certs) >= 7
