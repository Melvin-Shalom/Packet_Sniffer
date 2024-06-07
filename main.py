import struct
import socket
import requests
import json
import time
from collections import Counter
from prettytable import PrettyTable
from termcolor import colored

def get_mac_addr(bytes_addr):
    try:
        bytes_str = map("{:02x}".format, bytes_addr)
        return ':'.join(bytes_str).upper()
    except Exception as e:
        print(f"Error converting MAC address: {e}")
        return "00:00:00:00:00:00"

def get_ipv4(addr):
    try:
        return '.'.join(map(str, addr))
    except Exception as e:
        print(f"Error converting IPv4 address: {e}")
        return "0.0.0.0"

def parse_frame(frame):
    try:
        eth_len = 14
        eth_header = frame[:eth_len]
        eth_data = frame[eth_len:]
        dest_mac, src_mac, proto = struct.unpack('!6s6sH', eth_header)
        dest_mac = get_mac_addr(dest_mac)
        src_mac = get_mac_addr(src_mac)
        
        proto = hex(proto)
        if proto == '0x800':
            ip_proto = 'IPv4'
        elif proto == '0x806':
            ip_proto = 'ARP'
        elif proto == '0x86DD':
            ip_proto = 'IPv6'
        else:
            ip_proto = proto
        
        print(colored('\n\n*********Ethernet Frame*********', 'green'))
        print(f"Source_MAC: {colored(src_mac, 'yellow')}\tDestination_MAC: {colored(dest_mac, 'yellow')}\nInternet Protocol: {colored(ip_proto, 'cyan')}")
        return eth_data, ip_proto
    except Exception as e:
        print(f"Error parsing Ethernet frame: {e}")
        return None, None

def parse_packet(packet):
    try:
        first_byte = packet[0]
        ip_version = first_byte >> 4
        ip_header_length = (first_byte & 15) * 4
        ttl, proto, src, dest = struct.unpack('!8xBB2x4s4s', packet[:20])
        
        src_ip = get_ipv4(src)
        dest_ip = get_ipv4(dest)
        
        src_web = rev_dnslookup(src_ip)
        dest_web = rev_dnslookup(dest_ip)
        
        if proto == 1:
            transport_proto = 'ICMP'
        elif proto == 6:
            transport_proto = 'TCP'
        elif proto == 17:
            transport_proto = 'UDP'
        else:
            transport_proto = 'Unknown Protocol Field = ' + str(proto)
        
        print(colored('---------IP Packet---------', 'green'))
        print(f"Source_IP: {colored(src_ip, 'yellow')}\tDestination_IP: {colored(dest_ip, 'yellow')}\nTTL: {colored(ttl, 'cyan')} hops\tTransport_Protocol: {colored(transport_proto, 'cyan')}")
        return packet[ip_header_length:], transport_proto
    except Exception as e:
        print(f"Error parsing IP packet: {e}")
        return None, None

def parse_ICMP(data):
    try:
        field_type = struct.unpack('!B', data[:1])[0]
        icmp_types = {
            0: 'Echo Reply',
            3: 'Destination Unreachable',
            4: 'Source Quench',
            5: 'Redirect Message',
            8: 'Echo Request',
            9: 'Router Advertisement',
            10: 'Router Solicitation',
            11: 'Time Exceeded',
            12: 'Parameter Problem: Bad IP header',
            13: 'Timestamp Request',
            14: 'Timestamp Reply',
            15: 'Information Request',
            16: 'Information Reply',
            17: 'Address Mask Request',
            18: 'Address Mask Reply',
            30: 'Traceroute'
        }
        icmp_type = icmp_types.get(field_type, 'Reserved or Deprecated')
        
        print(colored('---------ICMP Packet---------', 'green'))
        print(f"Type: {colored(icmp_type, 'cyan')}")
        return data[8:]
    except Exception as e:
        print(f"Error parsing ICMP packet: {e}")
        return None

def parse_UDP(data):
    try:
        src_port, dest_port, packet_length = struct.unpack('!HHH', data[:6])
        print(colored('---------UDP Packet---------', 'green'))
        print(f"Source_Port: {colored(src_port, 'yellow')}\tDestination_Port: {colored(dest_port, 'yellow')}\nPacket_Length: {colored(packet_length, 'cyan')}")
        return data[8:]
    except Exception as e:
        print(f"Error parsing UDP packet: {e}")
        return None

def parse_TCP(data):
    try:
        src_port, dest_port, seq, ack, offset_flags = struct.unpack('!HHLLH', data[:14])
        tcp_header_length = (offset_flags >> 12) * 4
        
        flag_urg = (offset_flags & 32) >> 5
        flag_ack = (offset_flags & 16) >> 4
        flag_psh = (offset_flags & 8) >> 3
        flag_rst = (offset_flags & 4) >> 2
        flag_syn = (offset_flags & 2) >> 1
        flag_fin = offset_flags & 1
        
        print(colored('---------TCP Packet---------', 'green'))
        print(f"Source_Port: {colored(src_port, 'yellow')}\tDestination_Port: {colored(dest_port, 'yellow')}\nHeader_Length: {colored(tcp_header_length, 'cyan')}")
        print(f"Sequence: {colored(seq, 'cyan')}")
        print(f"Acknowledgement: {colored(ack, 'cyan')}")
        print("Flags: URG ACK PSH RST SYN FIN")
        print(f"      {flag_urg:3} {flag_ack:3} {flag_psh:3} {flag_rst:3} {flag_syn:3} {flag_fin:3}")
        return data[tcp_header_length:]
    except Exception as e:
        print(f"Error parsing TCP packet: {e}")
        return None

def parse_transport_packet(data, protocol):
    try:
        application_packet = None
        if protocol == 'TCP':
            application_packet = parse_TCP(data)
        elif protocol == 'UDP':
            application_packet = parse_UDP(data)
        elif protocol == 'ICMP':
            application_packet = parse_ICMP(data)
        return application_packet
    except Exception as e:
        print(f"Error parsing transport packet: {e}")
        return None

def rev_dnslookup(ip_addr):
    try:
        ip_classes = [int(x) for x in ip_addr.split('.')]
        
        if ((ip_classes[0] == 10) or
            (ip_classes[0] == 172 and (16 <= ip_classes[1] <= 31)) or
            (ip_classes[0] == 192 and ip_classes[1] == 168)):
            print(f'Private IP Address: {ip_addr}')
            return 'private_ip'
        else:
            try:
                rdns_data = socket.gethostbyaddr(ip_addr)
                print(f"Domain Name: {rdns_data[0]}")
                print(f"Host IP: {rdns_data[2][0]}")
                return rdns_data[0]
            except socket.error:
                print("Domain Name not found.")
                return None
    except Exception as e:
        print(f"Error in reverse DNS lookup: {e}")
        return None

def main():
    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except socket.error as e:
        print(f"Socket could not be created. Error: {e}")
        return

    packet_count = Counter()
    start_time = time.time()

    while True:
        try:
            payload, addr = conn.recvfrom(65535)
            ip_packet, ip_protocol = parse_frame(payload)
            if ip_protocol == 'IPv4':
                packet_count['IPv4'] += 1
                transport_packet, transport_proto = parse_packet(ip_packet)
                if transport_packet and transport_proto:
                    packet_count[transport_proto] += 1
                    application_packet = parse_transport_packet(transport_packet, transport_proto)

            if time.time() - start_time > 10:
                start_time = time.time()
                table = PrettyTable(['Protocol', 'Packet Count'])
                for protocol, count in packet_count.items():
                    table.add_row([protocol, count])
                print(colored('\nPacket Statistics (Last 10 seconds):', 'magenta'))
                print(table)

        except Exception as e:
            print(f"Error receiving or processing packet: {e}")

if __name__ == "__main__":
    main()

