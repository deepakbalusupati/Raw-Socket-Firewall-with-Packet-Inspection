![Screenshot](firewall.png)

# Raw Socket Firewall with Packet Inspection 🔥

![Linux](https://img.shields.io/badge/Linux-Ubuntu%2022.04-orange)
![C++](https://img.shields.io/badge/C++-11/17-blue)
![Python](https://img.shields.io/badge/Python-3.10+-yellow)
![License](https://img.shields.io/badge/License-MIT-green)

## Table of Contents 📋
1. [Features](#features-)
2. [Prerequisites](#prerequisites-)
3. [Installation](#installation-)
4. [Configuration](#configuration-)
5. [Usage](#usage-)
6. [Web Interface](#web-interface-)
7. [Testing](#testing-)
8. [Project Structure](#project-structure-)
9. [Troubleshooting](#troubleshooting-)
10. [Contributing](#contributing-)
11. [License](#license-)

## Features ✨
- **Layer 3/4 Packet Filtering** (TCP/UDP/ICMP)
- **Deep Packet Inspection** (HTTP payload analysis)
- **Web-Based Control Panel** (Flask/Python)
- **Real-Time Traffic Monitoring**
- **Custom Rule Engine**
- **Attack Protection** (SQLi, XSS, Port Scans)

## Prerequisites 📦
### Ubuntu/Debian (22.04)
```bash
sudo apt update && sudo apt install -y \
    build-essential \
    cmake \
    libpcap-dev \
    python3 \
    python3-pip \
    git \
    libmicrohttpd-dev

Installation ⚙️
1. Clone and Build
bash
git clone https://github.com/yourusername/Raw-Socket-Firewall.git
cd Raw-Socket-Firewall
mkdir build && cd build
cmake .. && make
sudo make install
2. Verify Installation
bash
firewall --version
# Expected output: "Raw Socket Firewall v1.0"
Configuration ⚙️
Rule Files
Main Rules (config/firewall.rules):

plaintext
# Format: action protocol source destination port
allow tcp * * 22      # Allow SSH
deny udp * * 123      # Block NTP
allow tcp * * 80       # HTTP
allow tcp * * 443      # HTTPS
deny * * * *           # Default deny
Blacklist (config/blacklist.txt):

plaintext
10.0.0.5
192.168.1.100
Whitelist (config/whitelist.txt):

plaintext
192.168.1.1
Usage 🚀
Command Line
bash
# Start with auto-detected interface
sudo firewall

# Specify interface
sudo firewall eth0

# List available interfaces
firewall --list-interfaces
Systemd Service (Production)
ini
# Create /etc/systemd/system/firewall.service
[Unit]
Description=Raw Socket Firewall
After=network.target

[Service]
ExecStart=/usr/local/bin/firewall eth0
Restart=always
User=root

[Install]
WantedBy=multi-user.target
Then:

bash
sudo systemctl enable firewall
sudo systemctl start firewall
Web Interface 🌐
Launch
bash
cd web
pip3 install flask
python3 app.py
Access at: http://localhost:5000

Interface Preview
┌───────────────────────────────────────┐
│ Raw Socket Firewall Control Panel     │
├───────────────────────────────────────┤
│ [✓] Firewall Status: RUNNING          │
│ Network Interface: eth0               │
├───────────────────────────────────────┤
│ [Start] [Stop]                        │
├───────────────────────────────────────┤
│ Rules:                                │
│ allow tcp * * 80                      │
│ deny udp * * 123                      │
└───────────────────────────────────────┘
Testing 🧪
1. Verify Allowed Traffic
bash
# HTTP (Port 80)
curl -v http://example.com

# DNS (Port 53 UDP)
nslookup example.com
2. Test Blocking
bash
# Blacklisted IP
ping 192.168.1.100

# Non-whitelisted port
telnet google.com 4444
3. Attack Simulation
bash
# SQL Injection (Blocked)
curl "http://localhost/?param='OR 1=1--"

# XSS Attempt (Blocked)
curl "http://localhost/?q=<script>alert(1)</script>"

# Port Scan (Blocks suspicious probes)
nmap -sS -T4 localhost
Project Structure 📂
Raw-Socket-Firewall/
├── build/               # Compiled binaries
├── config/              # Configuration
│   ├── firewall.rules   # Rule definitions
│   ├── blacklist.txt    # Blocked IPs
│   └── whitelist.txt    # Trusted IPs
├── src/                 # Source code
│   ├── include/         # Headers
│   └── impl/            # Implementation
├── web/                 # Web UI
│   ├── app.py           # Flask app
│   ├── templates/       # HTML
│   └── static/          # CSS/JS
└── tests/               # Test cases
Troubleshooting 🔧
1. Interface Errors
bash
# List available interfaces
ip -brief link show
# Sample output:
# lo      UNKNOWN    00:00:00:00:00:00 <LOOPBACK,UP,LOWER_UP>
# eth0    UP         aa:bb:cc:dd:ee:ff <BROADCAST,MULTICAST,UP,LOWER_UP>
2. Permission Issues
bash
# Rebuild with correct permissions
cd build && sudo cmake .. && sudo make
3. Web Interface Fails
bash
# Check Flask installation
pip3 show flask || pip3 install flask
Contributing 🤝
Fork the repository

Create your feature branch:

bash
git checkout -b feature/awesome-feature
Commit changes:

bash
git commit -m "Add awesome feature"
Push to branch:

bash
git push origin feature/awesome-feature
Open a Pull Request

License 📄
text
MIT License

Copyright (c) 2023 Your Name

Permission is hereby granted... (full license text)