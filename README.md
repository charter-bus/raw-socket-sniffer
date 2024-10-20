# raw-socket-sniffer
IP traffic sniffer in Python using raw sockets, without the Scapy module.
<br>
<br>
The most "feature-rich" script in this set of sniffers, is the <code>scanner.py</code>.
<br>
The <code>scanner.py</code> features:
- IP data structure class for interacting with the IP headers
- ICMP data structure class for interacting with individual ICMP values
- Threading
- UDP Packet Spray on Target Subnet
- Response Logging and Saving of Live/Responding Hosts
- "Promiscuous" and "non-promiscuous" mode handling if on Windows
<br>
<br>
Designed for host discovery by sending UDP packets to ports on potentially existing hosts on a network.
<br>
<br>
If a host exists, it will likely respond with an ICMP packet (unless that device has been configured *not* to respond with ICMP.)
<br>
<br>
We use UDP for this, since, TCP packets require more processing due to the conversation nature between two hosts, such as with ACK/SYN packets.
<br>
<br>
UDP has no delivery assurance mechanisms, and is more suitable for spray-and-pray over a network.
<br>
<br>
