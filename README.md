# Packet Sniffer

## Discription

The Network Sniffer is a Console Based Application based on **Python** that allows you to capture and analyze network packets in real-time. It provides insights into the types of packets being transmitted over the network, including Ethernet frames, IP packets, and transport layer protocols such as **TCP**, **UDP**, and **ICMP**. Additionally, a **virtual environment** was set up to manage dependencies effectively. The required modules are documented in a file named ***requirements.txt***.

To know how the Virtual Environment works, [visit here](https://www.freecodecamp.org/news/how-to-setup-virtual-environments-in-python/).

## Features

- Captures and analyzes Ethernet frames to extract MAC addresses and protocol information.
- Parses IP packets to determine source and destination IP addresses, TTL (Time-To-Live), and transport layer protocol.
- Supports parsing of ICMP, TCP, and UDP packets to extract specific protocol details.
- Provides real-time updates on captured packets, displaying packet details and protocol information as they are intercepted.
- Includes packet statistics functionality to track the count of packets per protocol and display statistics every 10 seconds.

## Requirements

- Python 3.11
- Terminal or Command Prompt

## Step for Execution

1. #### Open the Terminal and Clone the Repository
   ```
   git clone https://github.com/Melvin-Shalom/Packet_Sniffer.git
   ```
2. #### Navigate to the project directory
   ```
   cd Packet_Sniffer/
   ```
3. #### Activate the Virtualenv
   ```
   source venv/bin/activate
   ```
4. #### Install the Requirements
   ```
   pip install -r requirements.txt
   ```
5. #### Execute the Python script:
   ```
   sudo /venv/bin/python3 main.py
   ```
