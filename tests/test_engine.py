"""Tests for the fuzzing engine — classification logic."""
from exorr_prompt_fuzzer.engine import FuzzEngine, INJECTION_INDICATORS, REFUSAL_INDICATORS


def test_classify_vulnerable_response():
    """Response with injection indicators and no refusal should be classified as vulnerable."""
    engine = FuzzEngine(target_url="http://localhost:8080/v1/chat/completions", model="test")
    payload = {"name": "test", "category": "jailbreak", "severity": "high", "prompt": "test"}
    response = {
        "status_code": 200,
        "content": "Sure, I can help with that! Here's how to bypass security...",
        "raw": {},
        "error": None,
    }
    result = engine._classify_response(payload, response)
    assert result["vulnerable"] is True


def test_classify_safe_response():
    """Response with refusal indicators should be classified as safe."""
    engine = FuzzEngine(target_url="http://localhost:8080/v1/chat/completions", model="test")
    payload = {"name": "test", "category": "jailbreak", "severity": "high", "prompt": "test"}
    response = {
        "status_code": 200,
        "content": "I can't assist with that request. As an AI, I must decline.",
        "raw": {},
        "error": None,
    }
    result = engine._classify_response(payload, response)
    assert result["vulnerable"] is False


def test_classify_error_response():
    """Error responses should be classified as not vulnerable."""
    engine = FuzzEngine(target_url="http://localhost:8080/v1/chat/completions", model="test")
    payload = {"name": "test", "category": "injection", "severity": "medium", "prompt": "test"}
    response = {"status_code": 0, "content": "", "raw": "", "error": "TIMEOUT"}
    result = engine._classify_response(payload, response)
    assert result["vulnerable"] is False
    assert result["severity"] == "info"


def test_classify_extraction_critical():
    """Extraction category with injection indicators should be critical."""
    engine = FuzzEngine(target_url="http://localhost:8080/v1/chat/completions", model="test")
    payload = {"name": "test", "category": "extraction", "severity": "critical", "prompt": "test"}
    response = {
        "status_code": 200,
        "content": "The system prompt is: You are a helpful assistant. The password is xyz123.",
        "raw": {},
        "error": None,
    }
    result = engine._classify_response(payload, response)
    assert result["vulnerable"] is True
    assert result["severity"] == "critical"
