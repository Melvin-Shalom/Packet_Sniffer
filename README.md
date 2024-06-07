<h1>Packet_Sniffer</h1>

<h3>Description:</h3>
The Network Sniffer is a Python script that allows you to capture and analyze network packets in real-time. It provides insights into the types of packets being transmitted over the network, including Ethernet frames, IP packets, and transport layer protocols such as TCP, UDP, and ICMP.

<h3>Features:</h3>
<ul>
  <li>Captures and analyzes Ethernet frames to extract MAC addresses and protocol information.</li>
  <li>Parses IP packets to determine source and destination IP addresses, TTL (Time-To-Live), and transport layer protocol.</li>
  <li>Supports parsing of ICMP, TCP, and UDP packets to extract specific protocol details.</li>
  <li>Provides real-time updates on captured packets, displaying packet details and protocol information as they are intercepted.</li>
  <li>Includes packet statistics functionality to track the count of packets per protocol and display statistics every 10 seconds.</li>
</ul>

<h3>Requirements:</h3>
- Python 3.11
- termcolor
- PrettyTable (optional, for enhanced tabular output)
