```yaml
project:
  name: "Network Traffic Analyzer (Python)"
  badges:
    - "Status: Complete"
    - "Language: Python 3.x"
    - "License: MIT"

overview:
  description: >
    A Python-based Command-Line Interface (CLI) tool designed for real-time
    network traffic capture and packet inspection. It detects available network
    interfaces, captures packets in real-time, and displays detailed summaries
    to help users understand network behavior, debug issues, and analyze protocol activity.

key_features:
  automatic_interface_detection: "Lists all available network interfaces including Ethernet, Wi-Fi, and Loopback."
  live_packet_capture:
    - "Shows packet details such as source/destination IP, ports, protocol type, and packet size."
    - "Displays flags, DNS queries, and important metadata."
  real_time_statistics:
    - "Packet count per protocol."
    - "Total bytes captured."
    - "Most active hosts."
    - "Traffic distribution insights."
  filtering_support:
    type: "Basic BPF (Berkeley Packet Filter)"
    examples:
      - "tcp"
      - "udp"
      - "host 192.168.1.50"
      - "port 443"
  protocol_inspection:
    protocols:
      - "TCP flags"
      - "UDP"
      - "ICMP"
      - "DNS queries"

demonstration:
  example_output: |
    [+] Available interfaces:
    1: eth0 (Ethernet)
    2: wlan0 (Wi-Fi)
    3: lo (Loopback)

    [?] Select interface number: 2
    → Sniffing on wlan0…

    [!] TCP 192.168.1.52:443 → 142.250.72.84:443
        Size: 66 bytes
        Flags: [S]
        Query: google.com

    [+] Live Stats:
        Total Packets: 154
        Protocols: TCP (85), UDP (60), ICMP (9)
        Top Host: 142.250.72.78 (Google)

installation:
  prerequisites:
    python: "Python 3.8+"
    pip: true
    admin_permissions: "Required for raw packet capture"
  setup:
    steps:
      - description: "Clone the repository"
        command: "git clone <YOUR REPOSITORY URL>"
      - description: "Navigate into the repository"
        command: "cd Network-Traffic-Analyzer-Python"
      - description: "Install dependencies"
        command: "pip install -r requirements.txt"
    notes:
      - "macOS/Linux users may require 'sudo' for packet capture"

usage:
  run_command: "python analyzer.py"
  instructions:
    - "Select an interface"
    - "Enter an optional filter"
    - "Begin live traffic capture"

project_structure:
  tree: |
    ├── analyzer.py
    ├── requirements.txt
    ├── README.md
    └── utils/
        └── parser.py

future_enhancements:
  - "Save packets to .pcap"
  - "Export statistics to CSV/JSON"
  - "Color-coded terminal output"
  - "Additional protocol decoders (HTTP, TLS, ARP, DHCP)"
  - "Optional GUI interface (Tkinter/PyQt)"
  - "Automatic report generation"

license:
  type: "MIT"
  note: "This project is licensed under the MIT License."
