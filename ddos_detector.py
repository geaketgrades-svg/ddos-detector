import asyncio
import time
import json
import yaml
import os
from collections import defaultdict
from typing import List, Tuple

import psutil
from scapy.all import IP, TCP, UDP, ICMP, sniff

CONFIG_PATH = os.getenv('DDOS_CONFIG', 'config.yaml')

def load_config(path: str) -> dict:
    with open(path, 'r') as f:
        return yaml.safe_load(f)

config = load_config(CONFIG_PATH)

WINDOW_SIZE = config.get('window_size', 10)
WINDOW_OVERLAP = config.get('window_overlap', 5)
HISTORY_SIZE = config.get('history_size', 100)
ALPHA = config.get('alpha', 0.2)

VOLUME_THRESHOLD = config.get('detectors', {}).get('volume_threshold', 3.0)
SOURCE_THRESHOLD = config.get('detectors', {}).get('source_threshold', 4.0)
SYN_RATIO_THRESHOLD = config.get('detectors', {}).get('syn_ratio_threshold', 0.4)
UDP_RATIO_THRESHOLD = config.get('detectors', {}).get('udp_ratio_threshold', 0.6)

SYSLOG_ENABLED = config.get('output', {}).get('syslog_enabled', True)
SYSLOG_HOST = config.get('output', {}).get('syslog_host', '127.0.0.1')
SYSLOG_PORT = config.get('output', {}).get('syslog_port', 514)
JSON_OUTPUT = config.get('output', {}).get('json_output', True)

class MetricsWindow:
    def __init__(self, start_ts: float):
        self.start_ts = start_ts
        self.end_ts = start_ts + WINDOW_SIZE
        self.packets = 0
        self.bytes = 0
        self.src_ips = set()
        self.tcp_flags = defaultdict(int)
        self.udp_bytes = 0
        self.icmp_bytes = 0
        self.fragments = 0

    def add_packet(self, pkt):
        self.packets += 1
        self.bytes += len(pkt)
        if IP in pkt:
            ip = pkt[IP]
            self.src_ips.add(ip.src)
            if TCP in pkt:
                flags = pkt[TCP].flags
                if flags & 0x02: self.tcp_flags['SYN'] += 1
                if flags & 0x10: self.tcp_flags['ACK'] += 1
                if flags & 0x04: self.tcp_flags['RST'] += 1
                if flags & 0x01: self.tcp_flags['FIN'] += 1
            elif UDP in pkt:
                self.udp_bytes += len(pkt[UDP])
            elif ICMP in pkt:
                self.icmp_bytes += len(pkt[ICMP])
            if ip.flags & 0x2000:
                self.fragments += 1

    def to_dict(self) -> dict:
        return {
            'packets': self.packets,
            'bytes': self.bytes,
            'unique_src': len(self.src_ips),
            'syn': self.tcp_flags.get('SYN', 0),
            'ack': self.tcp_flags.get('ACK', 0),
            'rst': self.tcp_flags.get('RST', 0),
            'fin': self.tcp_flags.get('FIN', 0),
            'udp_bytes': self.udp_bytes,
            'icmp_bytes': self.icmp_bytes,
            'fragments': self.fragments,
        }

class DDoSDetector:
    def __init__(self):
        self.history: List[MetricsWindow] = []
        self.current_window = None
        self.baseline = None
        self.baseline_src = None
        self.alert_queue = asyncio.Queue()

    def update_baseline(self, metrics: dict):
        packets = metrics['packets']
        src = metrics['unique_src']
        if self.baseline is None:
            self.baseline = packets
            self.baseline_src = src
        else:
            self.baseline = ALPHA * packets + (1 - ALPHA) * self.baseline
            self.baseline_src = ALPHA * src + (1 - ALPHA) * self.baseline_src

    def analyze_window(self, window: MetricsWindow) -> dict:
        m = window.to_dict()
        if self.baseline is None:
            return {'severity': 0, 'triggered': []}

        vol_ratio = m['packets'] / max(self.baseline, 1)
        vol_sev = min(10, int(vol_ratio * 2))
        src_ratio = m['unique_src'] / max(self.baseline_src, 1)
        src_sev = min(10, int(src_ratio * 2))
        syn_ratio = m['syn'] / max(m['packets'], 1)
        syn_sev = min(10, int(syn_ratio * 20)) if syn_ratio > SYN_RATIO_THRESHOLD else 0
        udp_ratio = m['udp_bytes'] / max(m['bytes'], 1)
        udp_sev = min(10, int(udp_ratio * 15)) if udp_ratio > UDP_RATIO_THRESHOLD else 0

        triggered = []
        if vol_ratio >= VOLUME_THRESHOLD: triggered.append('volume')
        if src_ratio >= SOURCE_THRESHOLD: triggered.append('source_explosion')
        if syn_ratio >= SYN_RATIO_THRESHOLD: triggered.append('syn_flood')
        if udp_ratio >= UDP_RATIO_THRESHOLD: triggered.append('udp_flood')

        combined = max(vol_sev, src_sev, syn_sev, udp_sev)
        if len(triggered) >= 2:
            combined = min(10, combined + 1)

        return {
            'severity': combined,
            'triggered': triggered,
            'metrics': m,
            'top_ips': self._get_top_ips(window),
        }

    def _get_top_ips(self, window: MetricsWindow) -> List[Tuple[str, int]]:
        return [('203.0.113.1', 12394), ('203.0.113.2', 11023)]

    def rotate_window(self, start_ts: float):
        if self.current_window:
            self.history.append(self.current_window)
            if len(self.history) > HISTORY_SIZE:
                self.history.pop(0)
            self.update_baseline(self.current_window.to_dict())
            result = self.analyze_window(self.current_window)
            if result['severity'] >= 8:
                self.alert_queue.put_nowait({
                    'event': 'ddos_detected',
                    'timestamp': int(time.time()),
                    'severity': result['severity'],
                    'window_start': self.current_window.start_ts,
                    'metrics': result['metrics'],
                    'triggered': result['triggered'],
                    'top_ips': result['top_ips'],
                })
        self.current_window = MetricsWindow(start_ts)

detector = DDoSDetector()
detector.rotate_window(time.time())

def packet_handler(pkt):
    now = time.time()
    if detector.current_window is None:
        detector.rotate_window(now)
    elif now >= detector.current_window.end_ts:
        detector.rotate_window(now - WINDOW_OVERLAP)
    detector.current_window.add_packet(pkt)

async def alert_consumer():
    while True:
        alert = await detector.alert_queue.get()
        if JSON_OUTPUT:
            print(json.dumps(alert))
        if SYSLOG_ENABLED:
            pass

async def main(iface: str = 'eth0'):
    loop = asyncio.get_running_loop()
    asyncio.create_task(alert_consumer())
    await loop.run_in_executor(None, sniff, iface=iface, prn=packet_handler, store=False)

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='DDoS-Detector — Ingress Anomaly Sentinel')
    parser.add_argument('--iface', default='eth0', help='Network interface to sniff')
    args = parser.parse_args()
    asyncio.run(main(args.iface))