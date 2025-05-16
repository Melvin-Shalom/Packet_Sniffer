<h1>Packet Sniffer</h1>

<h2>Description</h2>
<p>
  The Network Sniffer, a Python-based tool, offers real-time packet capture and analysis, providing insights into various network protocols.
</p>

<h2>Features</h2>
<ul>
  <li>Captures and analyzes Ethernet frames to extract MAC addresses and protocol information.</li>
  <li>Parses IP packets to determine source and destination IP addresses, TTL (Time-To-Live), and transport layer protocol.</li>
  <li>Supports parsing of ICMP, TCP, and UDP packets to extract specific protocol details.</li>
  <li>Provides real-time updates on captured packets, displaying packet details and protocol information as they are intercepted.</li>
  <li>Includes packet statistics functionality to track the count of packets per protocol and display statistics every 10 seconds.</li>
</ul>

<h2>Requirements</h2>
<ul>
  <li>Python 3.11</li>
  <li>Terminal or Command Prompt</li>
</ul>

## Steps to Run

1. **Clone the repository**

   ```bash
   git clone https://github.com/Melvin-Shalom/Packet_Sniffer.git
   ```

2. **Navigate to the project directory**

   ```bash
   cd Packet_Sniffer/
   ```

3. **Create & activate the virtual environment**

   ```bash
   python -m venv venv
   source venv/bin/activate    # For Linux/macOS
   .\venv\Scripts\activate     # For Windows
   ```

4. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

5. **Run the packet sniffer script**

   ```bash
   sudo venv/bin/python3 main.py   # For Linux/macOS
   python main.py                  # For Windows
   ```


<h2>Usage</h2>
<p>
  Run the script to capture and analyze packets. Stats are printed every 10 seconds, providing protocol-wise packet distribution.
</p>

<h2>Future Scope</h2>
<ul>
  <li>Add GUI for live traffic visualization</li>
  <li>Export packet logs in .pcap format</li>
  <li>Filter packets by IP, port, or protocol</li>
  <li>Integrate with threat intelligence APIs</li>
</ul>

<h2>Author</h2>
<p>Built with ❤️ and ☕ by <a href="https://github.com/Melvin-Shalom">Melvin Shalom</a></p>

<h2>License</h2>
<p>Licensed under the <a href="https://opensource.org/licenses/MIT">MIT License</a></p>
