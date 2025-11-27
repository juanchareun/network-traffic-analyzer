Network Traffic Analyzer (Python)

🌐 Project Overview

This is a Python-based command-line tool designed for real-time network traffic capture and detailed analysis. It provides an essential utility for monitoring network activity, debugging communication issues, and learning about various networking protocols by examining raw packet data.

The tool leverages powerful external libraries (like scapy or pyshark, depending on your requirements.txt) to process data link layer information and present it in a human-readable format.

💡 Key Features & Analysis

The Network Analyzer provides a multi-faceted approach to traffic inspection:

Interface Selection: Automatically detects and lists all available network interfaces, allowing the user to select the specific interface for capture.

Live Packet Capture: Captures packets in real-time from the selected interface.

Detailed Packet Inspection: Decodes and displays essential information for each packet, including:

Source and Destination IP addresses.

Source and Destination Ports.

Protocol type (TCP, UDP, ICMP, etc.).

Payload size and summary.

Real-time Statistics: Maintains and displays live statistics on the captured traffic, such as packet counts per protocol, byte volumes, and common sources/destinations.

Filtering Capabilities: (Assuming basic filtering logic) Supports simple BPF (Berkeley Packet Filter) syntax to focus the capture on specific traffic (e.g., only TCP traffic, or traffic to a specific IP).

🖥️ Demonstration

To quickly understand the analyzer's functionality, here is an example of the typical output when capturing traffic on a network interface:

[+] Available Interfaces:
1: eth0 (Ethernet)
2: wlan0 (Wi-Fi)
3: lo (Loopback)

[?] Select interface number to sniff: 2
[--- Sniffing on wlan0 ---]

[#1] TCP 192.168.1.10:54321 -> 142.250.72.78:443 (Size: 66 bytes) [Flags: S]
[#2] TCP 142.250.72.78:443 -> 192.168.1.10:54321 (Size: 66 bytes) [Flags: SA]
[#3] UDP 192.168.1.10:5342 -> 8.8.8.8:53 (Query: google.com)
...

[+] Live Stats:
Total Packets: 154
Protocols: TCP (85), UDP (60), ICMP (9)
Top Host: 142.250.72.78 (Google)


⚙️ Installation & Usage

Prerequisites

Python 3.x (Required)

A C-Compiler (Often needed for network libraries like scapy on some systems)

Setup

Clone the repository:

git clone [Your Repository URL Here]


Navigate to the project directory:

cd Network-Traffic-Analyzer-FIX


Install dependencies:
The necessary libraries are listed in requirements.txt.

pip install -r requirements.txt


Note: On Linux/macOS, you may need to use sudo for permissions to access network interfaces for sniffing.

How to Run

Execute the script directly from your terminal:

python analyzer.py


Follow the on-screen prompts to select the network interface and initiate the capture.
