import os
from unittest.mock import patch, MagicMock

from src.tp1.utils.report import Report


def make_capture(protocols=None, alerts=None):
    capture = MagicMock()
    capture.protocol_counts = protocols if protocols is not None else {"TCP": 10, "UDP": 5, "ARP": 2}
    capture.alerts = alerts if alerts is not None else []
    return capture


def make_report(protocols=None, alerts=None):
    return Report(make_capture(protocols, alerts), "test.pdf", "Test summary")


# ── Initialisation ─────────────────────────────────────────────────────────────

def test_report_init():
    report = make_report()
    assert report.filename == "test.pdf"
    assert report.title == "Rapport d'Analyse Reseau - TP1 IDS/IPS"
    assert report.summary == "Test summary"
    assert report.array == []
    assert report.graph == []


# ── concat_report ──────────────────────────────────────────────────────────────

def test_concat_report_contains_title():
    report = make_report()
    assert "Rapport" in report.concat_report()


def test_concat_report_contains_summary():
    report = make_report()
    assert "Test summary" in report.concat_report()


# ── generate("array") ─────────────────────────────────────────────────────────

def test_generate_array_contains_protocols():
    report = make_report({"TCP": 10, "UDP": 5})
    report.generate("array")
    assert ("TCP", 10) in report.array
    assert ("UDP", 5) in report.array


def test_generate_array_empty_protocols():
    report = make_report({})
    report.generate("array")
    assert report.array == []


# ── generate("graph") ─────────────────────────────────────────────────────────

def test_generate_graph_sorted_desc():
    report = make_report({"UDP": 5, "TCP": 10})
    with patch("pygal.Bar") as mock_pygal:
        mock_chart = MagicMock()
        mock_pygal.return_value = mock_chart
        with patch("tempfile.NamedTemporaryFile", MagicMock()):
            report.generate("graph")
    assert report.graph[0] == ("TCP", 10)
    assert report.graph[1] == ("UDP", 5)


def test_generate_graph_empty_protocols():
    report = make_report({})
    report.generate("graph")
    assert report.graph == []


# ── generate("invalid") ───────────────────────────────────────────────────────

def test_generate_invalid_param_does_nothing():
    report = make_report()
    report.generate("invalid")
    assert report.graph == []
    assert report.array == []


# ── save() ────────────────────────────────────────────────────────────────────

def test_save_creates_pdf_file(tmp_path):
    report = make_report()
    report.generate("array")
    report.graph = [("TCP", 10), ("UDP", 5)]
    output = str(tmp_path / "report.pdf")
    report.save(output)
    assert os.path.exists(output)
    assert os.path.getsize(output) > 0


def test_save_pdf_with_alerts(tmp_path):
    alerts = [{
        "type": "ARP Spoofing", "protocol": "ARP",
        "src_ip": "10.0.0.1", "src_mac": "aa:bb:cc:dd:ee:ff",
        "detail": "IP revendiquée par deux MACs",
    }]
    report = make_report(alerts=alerts)
    report.generate("array")
    report.graph = [("ARP", 5)]
    output = str(tmp_path / "report_alerts.pdf")
    report.save(output)
    assert os.path.exists(output)
    assert os.path.getsize(output) > 0


def test_save_pdf_no_protocols(tmp_path):
    report = make_report({})
    output = str(tmp_path / "empty.pdf")
    report.save(output)
    assert os.path.exists(output)
