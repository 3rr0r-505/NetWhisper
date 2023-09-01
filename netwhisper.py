import argparse
from scapy.all import *

def capture_packets(interface, count, ip_address, save_file, tcp_only, hex_ascii):
    packets = sniff(iface=interface, count=count, filter=ip_address, prn=lambda pkt: process_packet(pkt, hex_ascii))
    
    if save_file:
        wrpcap(save_file, packets)
    
def process_packet(packet, hex_ascii=False):
    print(packet.show())
    if hex_ascii:
        print(packet.summary())
        print(packet.hexdump())
    
def display_interfaces():
    print(get_if_list())

def main():
    parser = argparse.ArgumentParser(description="NetWhisper - Network Packet Sniffer Tool")
    parser.add_argument("-i", "--interface", help="Network interface to capture packets from")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture")
    parser.add_argument("-ip", "--ip_address", help="Capture packets with the specified IP address")
    parser.add_argument("-s", "--save_file", help="Save captured packets to a file")
    parser.add_argument("-r", "--read_file", help="Read captured packets from a file")
    parser.add_argument("-tcp", "--tcp_only", action="store_true", help="Capture only TCP packets")
    parser.add_argument("-hexascii", "--hex_ascii", action="store_true", help="Display packets in HEX and ASCII values")
    args = parser.parse_args()

    if args.read_file:
        packets = rdpcap(args.read_file)
        for packet in packets:
            process_packet(packet, args.hex_ascii)
    else:
        if args.interface is None:
            display_interfaces()
            return
        capture_packets(args.interface, args.count, args.ip_address, args.save_file, args.tcp_only, args.hex_ascii)

if __name__ == "__main__":
    main()
