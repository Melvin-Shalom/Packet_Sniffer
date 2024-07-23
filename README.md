<h1>Packet Sniffer</h1>

<h2>Discription</h2>
<p>The Network Sniffer is a Console Based Application based on <strong>Python</strong> that allows you to capture and analyze network packets in real-time. It provides insights into the types of packets being transmitted over the network, including Ethernet frames, IP packets, and transport layer protocols such as <strong>TCP</strong>, <strong>UDP</strong>, and <strong>ICMP</strong>. Additionally, a <strong>virtual environment</strong> was set up to manage dependencies effectively. The required modules are documented in a file named <strong><em>requirements.txt</em></strong>.
</p>

<p>To know how the Virtual Environment works, <a href="https://www.freecodecamp.org/news/how-to-setup-virtual-environments-in-python/" target="_blank">visit here</a>.</p>

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

<h2>Step for Execution</h2>
<ol>
	<li>
		<h4>Open the Terminal and Clone the Repository</h4>
		<code>git clone https://github.com/Melvin-Shalom/Packet_Sniffer.git</code><br>
	</li>
	<li>
		<h4>Navigate to the project directory</h4>
		<code>cd Packet_Sniffer/</code>
	</li>
	<li>
		<h4>Activate the Virtualenv</h4>
		<code>source venv/bin/activate</code>
	</li>
	<li>
		<h4>Install the Requirements</h4>
		<code>pip install -r requirements.txt</code>
	</li>
	<li>
		<h4>Execute the Python script:</h4>
		<code>sudo /venv/bin/python3 main.py</code>
	</li>
</ol>
