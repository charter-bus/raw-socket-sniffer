# raw-socket-sniffer
IP traffic sniffer in Python using raw sockets.

Designed for host discovery by sending UDP packets to ports on potentially existing hosts on a network.
<br>
If a host exists, it will likely respond with an ICMP packet (unless that device has been configured *not* to respond with ICMP.)
<br>
We use UDP for this, since, TCP packets require more processing due to the conversation nature between two hosts, such as with ACK/SYN packets.
<br>
UDP has no delivery assurance mechanisms, and is more suitable for spray-and-pray over a network.
<br>
