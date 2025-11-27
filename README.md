# 📡 Network Traffic Analyzer (Python)

[![Project Status](https://img.shields.io/badge/Status-Complete-brightgreen)]()
[![Language](https://img.shields.io/badge/Language-Python%203.x-blue)]()
[![License](https://img.shields.io/badge/License-MIT-lightgrey)]()

## 💡 Project Overview

This is a Python-based **Command-Line Interface (CLI)** tool designed for **real-time network traffic capture and detailed packet inspection**.  
It provides the essential functionality needed for:

- Monitoring network activity  
- Debugging communication issues  
- Understanding how network protocols behave  
- Learning packet-level analysis  

The analyzer automatically detects available network interfaces, captures live packets, and displays readable summaries that help users visualize what's happening on a network in real time.

---

## 🧠 Key Features & Technical Capabilities

The tool delivers a multi-layered view of network activity using raw packet capture and protocol decoding:

### 🔍 **Automatic Interface Detection**
Identifies all active network interfaces (Ethernet, Wi-Fi, loopback).  
Users simply select where to capture traffic.

### 🚦 **Live Packet Capture**
Displays real-time packet flow including:
- Source & destination IP addresses  
- Ports  
- Protocol (TCP, UDP, ICMP, etc.)  
- Payload size  
- Flags and packet summary  

### 📊 **Traffic Statistics**
Generates ongoing metrics such as:
- Packet counts by protocol  
- Byte volume per protocol  
- Most active hosts  
- Distribution insights

### 🎯 **Filtering Support (Basic BPF Syntax)**
Allows the user to focus on specific traffic:
- TCP only  
- UDP only  
- Traffic to/from a specific IP  
- Simple Berkeley Packet Filter expressions  

### 🧩 **Detailed Protocol Inspection**
Shows deeper insights where applicable:
- DNS queries  
- TCP flags  
- Payload metadata  

---

## 🚀 Installation & Usage

### 🔧 Prerequisites
- **Python 3.8+**
- **pip**
- **Administrator/root permissions** (required for raw packet capture)



