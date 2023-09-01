<p align="center"><a href="https://github.com/3rr0r-505/NetWhisper"><img alt="" src="https://github.com/3rr0r-505/NetWhisper/blob/master/NetWhisper-cover.png?raw=true" width="100%"/></a></p>

<p align="center"> 
<a href="https://www.python.org/"><img alt="" src="https://img.shields.io/badge/python-3.9%2B-brighten?logo=python&label=pyhton&color=blue"/></a>
&nbsp;
<a href="https://www.gnu.org/gnu/linux-and-gnu.en.html"><img alt="" src="https://img.shields.io/badge/OS-GNU%2FLINUX-brighten?logo=linux&label=OS&labelColor=grey&color=red"/></a>
&nbsp;
<a href="https://www.microsoft.com/en-us/windows?r=1"><img alt="" src="https://img.shields.io/badge/OS-Windows-brighten?logo=windows&label=OS&labelColor=grey&color=blue"/></a><br>
</p>

# NetWhisper - Network Packet Sniffer Tool

NetWhisper is a command-line tool for capturing and analyzing network packets.

### Demo
![NetWhisper Demo](https://github.com/3rr0r-505/NetWhisper/blob/master/netwhisper-cli-vid.gif)

## Features

- Capture packets from a specific network interface
- Capture a specific number of packets
- Capture packets with a specific IP address
- Capture only TCP packets
- Display packets in HEX and ASCII values
- Save captured packets to a file
- Read captured packets from a file
- Display available network interfaces

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/3rr0r-505/netwhisper.git

2. Navigate to the project directory:
   ```bash
   cd NetWhisper

3. Install the required dependencies using pip:
   ```bash
   pip install -r requirements.txt

## Usage
- Display all available network interfaces:
  ```bash
  python netwhisper.py

- Capture packets from a specific interface:
  ```bash
  python netwhisper.py -i eth0

- Capture a specific number of packets:
  ```bash
  python netwhisper.py -i eth0 -c 100

- Capture only TCP packets:
  ```bash
  python netwhisper.py -i eth0 -tcp

- Display packets in HEX and ASCII values:
  ```bash
  python netwhisper.py -i eth0 -hexascii

- Save captured packets to a file:
  ```bash
  python netwhisper.py -i eth0 -s captured_packets.pcap

- Read captured packets from a file:
  ```bash
  python netwhisper.py -r captured_packets.pcap

- **Note:**  
  If you encounter ```permission issues``` while capturing packets, try running the tool with ```sudo```: ```sudo python netwhisper.py -i eth0 -tcp```

## Legal Disclaimer
The use of code contained in this repository, either in part or in its totality,
for engaging targets without prior mutual consent is illegal. **It is
the end user's responsibility to obey all applicable local, state and
federal laws.**

Developers assume **no liability** and are not
responsible for misuses or damages caused by any code contained
in this repository in any event that, accidentally or otherwise, it comes to
be utilized by a threat agent or unauthorized entity as a means to compromise
the security, privacy, confidentiality, integrity, and/or availability of
systems and their associated resources. In this context the term "compromise" is
henceforth understood as the leverage of exploitation of known or unknown vulnerabilities
present in said systems, including, but not limited to, the implementation of
security controls, human- or electronically-enabled.

The use of this code is **only** endorsed by the developers in those
circumstances directly related to **educational environments** or
**authorized penetration testing engagements** whose declared purpose is that
of finding and mitigating vulnerabilities in systems, limiting their exposure
to compromises and exploits employed by malicious agents as defined in their
respective threat models.

## License
This project is licensed under the Apache License 2.0 - see the LICENSE file for details.
