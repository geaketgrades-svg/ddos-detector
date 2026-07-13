# DDoS-Detector — Ingress Anomaly Sentinel

**Passive, real-time volumetric anomaly detection for your network edge.**

---

## What It Does

- Captures packets from a mirror port (or live interface) using `scapy`.
- Aggregates traffic into sliding windows (10 seconds, 50% overlap).
- Maintains an adaptive baseline using Exponentially Weighted Moving Average (EWMA).
- Runs four parallel detectors:
    - Volume spike
    - Source IP explosion
    - SYN flood
    - UDP flood
- Raises alerts (JSON) to stdout and syslog when combined severity ≥ 8.
- No active response — detection only. No writes to disk except logs.

---

## Why This Exists

DDoS attacks are getting faster. Traditional threshold-based detection is too slow and too noisy. This detector uses an adaptive baseline and multiple orthogonal metrics to catch the first wave before your pipe saturates. It's built for security teams, SOC analysts, and edge engineers who need a sentry that doesn't sleep.

---

## Requirements

- Python 3.9+
- Linux (Debian/RHEL) with `libpcap` installed
- A network interface that receives traffic (mirror port or cloud VPC flow logs)

---

## Installation

```bash
# Clone the repo
git clone https://github.com/your-org/ddos-detector.git
cd ddos-detector

# Install dependencies
pip install -r requirements.txt

# Run as root (required for packet capture)
sudo python3 ddos_detector.py --iface eth0
