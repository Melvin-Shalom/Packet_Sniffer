# Packet_Sniffer

## Description:
The Network Sniffer is a Python script that allows you to capture and analyze network packets in real-time. It provides insights into the types of packets being transmitted over the network, including Ethernet frames, IP packets, and transport layer protocols such as TCP, UDP, and ICMP.

## Features:
- Captures and analyzes Ethernet frames to extract MAC addresses and protocol information.
- Parses IP packets to determine source and destination IP addresses, TTL (Time-To-Live), and transport layer protocol.
- Supports parsing of ICMP, TCP, and UDP packets to extract specific protocol details.
- Provides real-time updates on captured packets, displaying packet details and protocol information as they are intercepted.
- Includes packet statistics functionality to track the count of packets per protocol and display statistics every 10 seconds.

## Requirements:
- Python 3.11
- termcolor
- PrettyTable (optional, for enhanced tabular output)
