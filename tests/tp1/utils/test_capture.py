from unittest.mock import patch, MagicMock

from scapy.all import Ether, ARP, IP, TCP, Raw

from src.tp1.utils.capture import Capture


def make_capture(interface="eth0"):
    """Helper: create a Capture without prompting the user."""
    with patch("src.tp1.utils.capture.choose_interface", return_value=interface):
        return Capture()


# ── Initialisation ─────────────────────────────────────────────────────────────

def test_capture_init():
    capture = make_capture()
    assert capture.interface == "eth0"
    assert capture.summary == ""
    assert capture.packets == []
    assert capture.alerts == []


# ── Protocol helpers ───────────────────────────────────────────────────────────

def test_sort_network_protocols_empty():
    capture = make_capture()
    assert capture.sort_network_protocols() == ""


def test_sort_network_protocols_sorted_desc():
    capture = make_capture()
    capture.protocol_counts["TCP"] = 10
    capture.protocol_counts["UDP"] = 5
    result = capture.sort_network_protocols()
    assert "TCP: 10" in result
    assert "UDP: 5" in result
    assert result.index("TCP") < result.index("UDP")


def test_get_all_protocols_empty():
    capture = make_capture()
    assert capture.get_all_protocols() == ""


def test_get_all_protocols_contains_data():
    capture = make_capture()
    capture.protocol_counts["ARP"] = 3
    assert "ARP: 3" in capture.get_all_protocols()


# ── ARP Spoofing ───────────────────────────────────────────────────────────────

def test_detect_arp_spoofing_two_macs_same_ip():
    capture = make_capture()
    pkt1 = Ether() / ARP(op=2, psrc="192.168.1.1", hwsrc="aa:bb:cc:dd:ee:ff")
    pkt2 = Ether() / ARP(op=2, psrc="192.168.1.1", hwsrc="11:22:33:44:55:66")
    capture.packets = [pkt1, pkt2]
    alerts = capture._detect_arp_spoofing()
    assert len(alerts) == 1
    assert alerts[0]["type"] == "ARP Spoofing"
    assert alerts[0]["src_ip"] == "192.168.1.1"
    assert alerts[0]["protocol"] == "ARP"


def test_detect_arp_spoofing_same_mac_no_alert():
    capture = make_capture()
    pkt = Ether() / ARP(op=2, psrc="192.168.1.1", hwsrc="aa:bb:cc:dd:ee:ff")
    capture.packets = [pkt, pkt]
    assert capture._detect_arp_spoofing() == []


def test_detect_arp_spoofing_arp_request_ignored():
    capture = make_capture()
    # op=1 is ARP request, should not trigger detection
    pkt = Ether() / ARP(op=1, psrc="192.168.1.1", hwsrc="aa:bb:cc:dd:ee:ff")
    capture.packets = [pkt]
    assert capture._detect_arp_spoofing() == []


# ── SQL Injection ──────────────────────────────────────────────────────────────

def test_detect_sql_injection_select():
    capture = make_capture()
    pkt = Ether() / IP(src="10.0.0.1") / TCP(dport=80) / Raw(load=b"SELECT * FROM users")
    capture.packets = [pkt]
    alerts = capture._detect_sql_injection()
    assert len(alerts) == 1
    assert alerts[0]["type"] == "SQL Injection"
    assert alerts[0]["src_ip"] == "10.0.0.1"


def test_detect_sql_injection_drop():
    capture = make_capture()
    pkt = Ether() / IP(src="10.0.0.2") / TCP(dport=3306) / Raw(load=b"DROP TABLE users;")
    capture.packets = [pkt]
    alerts = capture._detect_sql_injection()
    assert len(alerts) == 1
    assert alerts[0]["type"] == "SQL Injection"


def test_detect_sql_injection_clean_traffic():
    capture = make_capture()
    pkt = Ether() / IP(src="10.0.0.1") / TCP(dport=80) / Raw(load=b"GET / HTTP/1.1\r\nHost: example.com")
    capture.packets = [pkt]
    assert capture._detect_sql_injection() == []


def test_detect_sql_injection_case_insensitive():
    capture = make_capture()
    pkt = Ether() / IP(src="10.0.0.1") / TCP(dport=80) / Raw(load=b"select * from admin")
    capture.packets = [pkt]
    alerts = capture._detect_sql_injection()
    assert len(alerts) == 1


# ── Port Scan ──────────────────────────────────────────────────────────────────

def test_detect_port_scan_above_threshold():
    capture = make_capture()
    capture.packets = [
        Ether() / IP(src="192.168.0.99") / TCP(dport=port, flags="S")
        for port in range(1, 20)  # 19 ports > threshold of 15
    ]
    alerts = capture._detect_port_scan()
    assert len(alerts) == 1
    assert alerts[0]["type"] == "Port Scan"
    assert alerts[0]["src_ip"] == "192.168.0.99"


def test_detect_port_scan_below_threshold():
    capture = make_capture()
    capture.packets = [
        Ether() / IP(src="10.0.0.1") / TCP(dport=port, flags="S")
        for port in range(1, 5)  # only 4 ports
    ]
    assert capture._detect_port_scan() == []


def test_detect_port_scan_non_syn_ignored():
    capture = make_capture()
    capture.packets = [
        Ether() / IP(src="10.0.0.1") / TCP(dport=port, flags="A")  # ACK, not SYN
        for port in range(1, 20)
    ]
    assert capture._detect_port_scan() == []


# ── analyse() ─────────────────────────────────────────────────────────────────

def test_analyse_calls_internal_methods():
    capture = make_capture()
    with (
        patch.object(capture, "get_all_protocols") as mock_get,
        patch.object(capture, "sort_network_protocols") as mock_sort,
        patch.object(capture, "_gen_summary", return_value="Test summary") as mock_gen,
    ):
        capture.analyse("tcp")

    mock_get.assert_called_once()
    mock_sort.assert_called_once()
    mock_gen.assert_called_once()
    assert capture.summary == "Test summary"


# ── get_summary / _gen_summary ─────────────────────────────────────────────────

def test_get_summary():
    capture = make_capture()
    capture.summary = "hello"
    assert capture.get_summary() == "hello"


def test_gen_summary_no_alerts():
    capture = make_capture()
    capture.alerts = []
    result = capture._gen_summary()
    assert "Tout va bien" in result


def test_gen_summary_with_alert():
    capture = make_capture()
    capture.alerts = [{
        "type": "ARP Spoofing", "protocol": "ARP",
        "src_ip": "10.0.0.1", "src_mac": "aa:bb:cc:dd:ee:ff",
        "detail": "test",
    }]
    result = capture._gen_summary()
    assert "ALERTES" in result
    assert "ARP Spoofing" in result
    assert "10.0.0.1" in result
