import time
import pytest
from ddos_detector import MetricsWindow, DDoSDetector

def test_metrics_window_initialization():
    w = MetricsWindow(time.time())
    assert w.packets == 0
    assert w.bytes == 0
    assert len(w.src_ips) == 0
    assert w.tcp_flags.get('SYN', 0) == 0
    assert w.udp_bytes == 0
    assert w.icmp_bytes == 0
    assert w.fragments == 0

def test_metrics_window_add_packet():
    # This test requires scapy packets to be fully meaningful
    # For now, we test the initialization and that the window stores start/end times
    start = time.time()
    w = MetricsWindow(start)
    assert w.start_ts == start
    assert w.end_ts == start + 10  # WINDOW_SIZE is 10 from config

def test_detector_baseline_updates():
    d = DDoSDetector()
    d.update_baseline({'packets': 100, 'unique_src': 5})
    assert d.baseline == 100
    assert d.baseline_src == 5

    d.update_baseline({'packets': 200, 'unique_src': 10})
    assert d.baseline > 100 and d.baseline < 200
    assert d.baseline_src > 5 and d.baseline_src < 10

def test_analyze_window_no_baseline():
    d = DDoSDetector()
    w = MetricsWindow(time.time())
    result = d.analyze_window(w)
    assert result['severity'] == 0
    assert result['triggered'] == []

def test_analyze_window_with_baseline_no_anomaly():
    d = DDoSDetector()
    d.update_baseline({'packets': 100, 'unique_src': 5})
    w = MetricsWindow(time.time())
    # Manually set metrics to match baseline
    w.packets = 100
    w.src_ips = {'192.168.1.1', '192.168.1.2', '192.168.1.3', '192.168.1.4', '192.168.1.5'}
    result = d.analyze_window(w)
    assert result['severity'] < 8
    assert result['triggered'] == []

def test_analyze_window_volume_spike():
    d = DDoSDetector()
    d.update_baseline({'packets': 100, 'unique_src': 5})
    w = MetricsWindow(time.time())
    w.packets = 500  # 5x baseline, should trigger volume
    w.src_ips = {'192.168.1.1'}
    result = d.analyze_window(w)
    assert 'volume' in result['triggered']

def test_analyze_window_syn_flood():
    d = DDoSDetector()
    d.update_baseline({'packets': 100, 'unique_src': 5})
    w = MetricsWindow(time.time())
    w.packets = 100
    w.tcp_flags['SYN'] = 60  # 60% SYN, above 40% threshold
    result = d.analyze_window(w)
    assert 'syn_flood' in result['triggered']

def test_analyze_window_udp_flood():
    d = DDoSDetector()
    d.update_baseline({'packets': 100, 'unique_src': 5})
    w = MetricsWindow(time.time())
    w.packets = 100
    w.bytes = 10000
    w.udp_bytes = 7000  # 70% UDP, above 60% threshold
    result = d.analyze_window(w)
    assert 'udp_flood' in result['triggered']

def test_rotate_window_creates_new_window():
    d = DDoSDetector()
    start = time.time()
    d.rotate_window(start)
    assert d.current_window is not None
    assert d.current_window.start_ts == start

def test_rotate_window_archives_old_window():
    d = DDoSDetector()
    d.rotate_window(time.time() - 20)  # force an old window
    old_window = d.current_window
    d.rotate_window(time.time())
    assert old_window in d.history

def test_severity_escalation_with_multiple_triggers():
    d = DDoSDetector()
    d.update_baseline({'packets': 100, 'unique_src': 5})
    w = MetricsWindow(time.time())
    w.packets = 400  # volume trigger
    w.tcp_flags['SYN'] = 50  # SYN trigger
    w.bytes = 10000
    w.udp_bytes = 7000  # UDP trigger
    result = d.analyze_window(w)
    # Should have at least volume and SYN (and possibly UDP if thresholds met)
    assert len(result['triggered']) >= 2
    # Severity should be boosted by 1 due to multiple triggers
    assert result['severity'] > 0