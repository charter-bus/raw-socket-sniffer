import socket
import os

# Define the host to listen on. Setting the local device IP is most common here.
HOST = 'your_host_address'

def main():
    # Check which OS the program is running on. 'nt' stands for "New Technology", in relation to the "NTFS" filesystem used by Windows.
    if os.name == 'nt':
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_ICMP
    
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((HOST, 0))
    # Set the socket option to include the IP header in the packet capture. Specified by the parameter, "IP_HDRINCL", meaning "Header Include".
    sniffer.setsockopt(socket.IPROTO_IP, socket.IP_HDRINCL, 1)

    # If running Windows, turn on "promiscuous mode", allowing us to view all network traffic, even if not designated to our host.
    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    
    # While in promiscuous mode, sniff a single packet.
    print(sniffer.recvfrom(65565))

    # If running Windows, turn off promiscuous mode.
    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

if __name__ == '__main__':
    main()