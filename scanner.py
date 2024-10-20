import ipaddress
from ctypes import *
import socket
import os
import struct
import sys
import threading
import time

# Subnet to target with UDP packets
SUBNET = '192.168.1.0/24'
MESSAGE = 'UDP_WITH_PYTHON_SCRIPT_MESSAGE'

# Define the data structure for the IP header portions.
class IP(Structure):
    # Each field of the IP header and the associated data type using C-based data types.
    _fields_ = [
        ("version",     c_ubyte,    4),  # 4 bit char, aka, a "nibble"
        ("ihl",         c_ubyte,    4),  # 4 bit char
        ("tos",         c_ubyte,    8),  # 1 byte char
        ("len",         c_ushort,   16), # 2 byte unsigned short, aka, a "word"
        ("id",          c_ushort,   16), # 2 byte unsigned short
        ("offset",      c_ushort,   16), # 2 byte unsigned short
        ("ttl",         c_ubyte,    8),  # 1 byte char
        ("protocol_num",c_ubyte,    8),  # 1 byte char
        ("sum",         c_ushort,   16), # 2 byte unsigned short
        ("src",         c_uint32,   32), # 4 byte unsigned integer, aka, a "double word"
        ("dst",         c_uint32,   32)  # 4 byte unsigned integer, aka, a "double word"
    ]

class ICMP:
    def __init__(self, buff):
        header = struct.unpack('<BBHHH', buff)
        self.type = header[0]
        self.code = header[1]
        self.sum = header[2]
        self.id = header[3]
        self.seq = header[4]

def __new__(cls, socket_buffer=None):
    return cls.from_buffer_copy(socket_buffer)

def __init__(self, socket_buffer=None):
    self.src_address = socket.inet_ntoa(struct.pack("<L",self.src))
    self.dst_address = socket.inet_ntoa(struct.pack("<L", self.dst))

def udp_sender():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        for ip in ipaddress.ip_network(SUBNET).hosts():
            sender.sendto(bytes(MESSAGE, 'utf8'), (str(ip), 65212))

class Scanner:
    def __init__(self, host):
        self.host = host
        if os.name == 'nt':
            socket_protocol = socket.IPPROTO_IP
        else:
            socket_protocol = socket.IPPROTO_ICMP
        
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
        self.socket.bind((host, 0))
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        if os.name == 'nt':
            self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

def sniff(self):
    hosts_up = set([f'{str(self.host)} *'])
    try:
        while True:
            raw_buffer = self.socket.recvfrom(65535)[0]
            ip_header = IP(raw_buffer[0:20])
            if ip_header.protocol == "ICMP":
                offset = ip_header.ihl * 4
                buf = raw_buffer[offset:offset + 8]
                icmp_header = ICMP(buf)

                if icmp_header.code == 3 and icmp_header.type == 3:
                    if ipaddress.ip_address(ip_header.src_address) in ipaddress.IPv4Network(SUBNET):
                        if raw_buffer[len(raw_buffer) - len(MESSAGE):] == bytes(MESSAGE, 'utf8'):
                            tgt = str(ip_header.src_address)
                            if tgt != self.host and tgt not in hosts_up:
                                hosts_up.add(str(ip_header.src_address))
                                print(f'Host Up: {tgt}')
                                # Append the IP address of the responding host to the file 'Hosts_Up.txt'
                                with open('Hosts_Up.txt', 'a') as file:
                                    file.write(f'{tgt}\n')
    except KeyboardInterrupt:
        if os.name == 'nt':
            self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        print('\nUser interrupted.')
        if hosts_up:
            print(f'\n\nSummary: Hosts up on {SUBNET}')
        for host in sorted(hosts_up):
            print(f'{host}')
        print('')
        sys.exit(0)

#! REPLACE 'HOST' variable on line 62.
if __name__ == '__main__':
    if len(sys.argv) == 2:
        host = sys.argv[1]
    else:
        host = 'HOST'
    s = Scanner(host)
    time.sleep(5)
    t = threading.Thread(target=udp_sender)
    t.start()
    s.sniff()