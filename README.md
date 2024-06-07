<h1>Packet_Sniffer</h1>

<h3>Overview</h3>
<p>The Network Sniffer is a <strong>Python</strong> script that allows you to capture and analyze network packets in real-time. It provides insights into the types of packets being transmitted over the network, including Ethernet frames, IP packets, and transport layer protocols such as <strong>TCP</strong>, <strong>UDP</strong>, and <strong>ICMP</strong>.Additionally, a <strong>virtual environment</strong> was set up to manage dependencies effectively. The required modules are documented in a file named <strong><em>requirements.txt</em></strong>.
</p>

<p>
  To know how the Virtual Environment works, <a href="https://www.freecodecamp.org/news/how-to-setup-virtual-environments-in-python/" target="_blank">visit here</a>.
</p>

<h2>Step for Execution:</h2>
<ol>
  <li>
    <strong>Activate the Virtualenv</strong><br>
    <small>Navigate to your project directory and activate the virtual environment:</small>
    <code>source venv/bin/activate</code>
  </li>
  <li>
    <strong>Execute the main.py file</strong><br>
    <small>Execute the Python script:</small>
    <code>sudo /venv/bin/python3 capture.py</code>
  </li>
</ol>

<h3>Features:</h3>
<ul>
  <li>Captures and analyzes Ethernet frames to extract MAC addresses and protocol information.</li>
  <li>Parses IP packets to determine source and destination IP addresses, TTL (Time-To-Live), and transport layer protocol.</li>
  <li>Supports parsing of ICMP, TCP, and UDP packets to extract specific protocol details.</li>
  <li>Provides real-time updates on captured packets, displaying packet details and protocol information as they are intercepted.</li>
  <li>Includes packet statistics functionality to track the count of packets per protocol and display statistics every 10 seconds.</li>
</ul>

<h3>Requirements:</h3>
<ul>
  <li>Python 3.11</li>
  <li>termcolor</li>
  <li>PrettyTable (optional, for enhanced tabular output)</li>
</ul>
