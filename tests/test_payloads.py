"""Tests for the payload loader module."""
import json
import tempfile
from pathlib import Path

from exorr_prompt_fuzzer.payloads import PayloadLoader, BUILTIN_PAYLOADS


def test_builtin_payloads_load():
    """Built-in payloads should load without error."""
    loader = PayloadLoader()
    payloads = loader.load_builtin()
    assert len(payloads) > 0, "Should have built-in payloads"
    assert len(payloads) == len(BUILTIN_PAYLOADS)


def test_builtin_payloads_structure():
    """Each built-in payload must have required fields."""
    loader = PayloadLoader()
    payloads = loader.load_builtin()
    required = {"name", "category", "severity", "prompt"}
    for p in payloads:
        assert required.issubset(set(p.keys())), f"Payload '{p.get('name')}' missing fields"


def test_builtin_categories():
    """Built-in payloads should cover expected categories."""
    loader = PayloadLoader()
    payloads = loader.load_builtin()
    categories = {p["category"] for p in payloads}
    expected = {"injection", "jailbreak", "extraction", "bypass", "encoding"}
    assert expected.issubset(categories), f"Missing categories: {expected - categories}"


def test_load_custom_file():
    """Custom payload files should load correctly."""
    custom = [
        {"name": "Test", "category": "injection", "severity": "high", "prompt": "test prompt"}
    ]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(custom, f)
        f.flush()
        loader = PayloadLoader()
        loaded = loader.load_file(Path(f.name))
        assert len(loaded) == 1
        assert loaded[0]["name"] == "Test"


def test_load_dir():
    """Loading a directory of payload files should work."""
    with tempfile.TemporaryDirectory() as tmpdir:
        for i in range(3):
            p = Path(tmpdir) / f"payloads_{i}.json"
            p.write_text(json.dumps([{"name": f"P{i}", "category": "injection", "severity": "low", "prompt": f"test {i}"}]))
        loader = PayloadLoader()
        loaded = loader.load_dir(Path(tmpdir))
        assert len(loaded) == 3
