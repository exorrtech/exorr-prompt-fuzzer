"""Tests for the report generator."""
import json
import tempfile
from pathlib import Path

from exorr_prompt_fuzzer.report import ReportGenerator


def _sample_results():
    return [
        {
            "payload_id": "abc123",
            "payload_name": "Direct Injection",
            "category": "injection",
            "prompt": "test prompt",
            "response_content": "Sure, here's how...",
            "status_code": 200,
            "vulnerable": True,
            "severity": "high",
            "reason": "Injection indicators found",
            "injection_indicators": ["i can"],
            "refusal_indicators": [],
            "error": None,
        },
        {
            "payload_id": "def456",
            "payload_name": "Safe Test",
            "category": "jailbreak",
            "prompt": "another test",
            "response_content": "I can't help with that.",
            "status_code": 200,
            "vulnerable": False,
            "severity": "info",
            "reason": "Refusal detected",
            "injection_indicators": [],
            "refusal_indicators": ["i can't"],
            "error": None,
        },
    ]


def test_json_report():
    """JSON report should be valid JSON with expected structure."""
    results = _sample_results()
    gen = ReportGenerator(results, target="http://test", model="test-model", format="json")
    report_json = gen._to_json()
    data = json.loads(report_json)
    assert data["scanner"] == "exorr-prompt-fuzzer"
    assert data["summary"]["vulnerable"] == 1
    assert data["summary"]["safe"] == 1


def test_markdown_report():
    """Markdown report should contain key sections."""
    results = _sample_results()
    gen = ReportGenerator(results, target="http://test", model="test-model", format="markdown")
    md = gen._to_markdown()
    assert "EXORR Prompt Fuzzer Report" in md
    assert "Vulnerabilities Found" in md


def test_html_report():
    """HTML report should be valid HTML."""
    results = _sample_results()
    gen = ReportGenerator(results, target="http://test", model="test-model", format="html")
    html = gen._to_html()
    assert "<html" in html
    assert "EXORR" in html


def test_save_report():
    """Report should save to file."""
    results = _sample_results()
    gen = ReportGenerator(results, target="http://test", model="test-model", format="json")
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        gen.save(f.name)
        data = json.loads(Path(f.name).read_text())
        assert data["summary"]["total_payloads"] == 2
