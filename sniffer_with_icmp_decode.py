import ipaddress
from ctypes import *
import socket
import os
import struct
import sys

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

def sniff(host):
    if os.name == 'nt':
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_ICMP
    
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

    sniffer.bind((host, 0))

    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    try:
        while True:
            raw_buffer = sniffer.recvfrom(65535)[0]
            ip_header = IP(raw_buffer[0:20])
            print('Protocol: %s %s -> $s' % (ip_header.protocol,
                                                ip_header.src_address,
                                                ip_header.dst_address))
            print(f'Version: {ip_header.ver}')
            print(f'Header Length: {ip_header.ihl} TTL: {ip_header.ttl}')

            offset = ip_header.ihl * 4
            buf = raw_buffer[offset:offset + 8]

            icmp_header = ICMP(buf)
            print('ICMP -> Type: %s Code: $s\n' % (icmp_header.type, icmp_header.code))

    except KeyboardInterrupt:
        if os.name == 'nt':
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        sys.exit()

#! REPLACE 'HOST' variable on line 62.
if __name__ == '__main__':
    if len(sys.argv) == 2:
        host = sys.argv[1]
    else:
        host = 'HOST'
    sniff(host)