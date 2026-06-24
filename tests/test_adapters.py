import pytest

from app.adapters.adapter_registry import detect_format, normalize_alert
from app.models.alert import AlertCategory, AlertSeverity

def test_splunk_detection():
    data = {
        "sid": "123",
        "search_name": "Test Alert",
        "result": {"src_ip": "1.1.1.1"}
    }
    assert detect_format(data) == "splunk"

def test_crowdstrike_detection():
    data = {
        "event": {
            "DetectName": "Malware",
            "SeverityName": "High"
        }
    }
    assert detect_format(data) == "crowdstrike"

def test_suricata_detection():
    data = {
        "event_type": "alert",
        "alert": {"signature": "Test"}
    }
    assert detect_format(data) == "suricata"

def test_generic_fallback():
    data = {"some_random_field": "value"}
    assert detect_format(data) == "generic"

def test_splunk_normalization():
    data = {
        "sid": "12345",
        "search_name": "Failed Login",
        "result": {
            "src_ip": "10.0.0.1",
            "user": "admin",
            "severity": "high"
        }
    }
    alert = normalize_alert(data)
    assert alert.id == "12345"
    assert alert.source_format == "splunk"
    assert alert.title == "Failed Login"
    assert alert.severity == AlertSeverity.HIGH
    assert alert.network.src_ip == "10.0.0.1"
    assert alert.user.username == "admin"
