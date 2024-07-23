import struct
import socket
import time
from collections import Counter
from prettytable import PrettyTable
from termcolor import colored
import logging
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_mac_addr(bytes_addr):
    try:
        return ':'.join(f"{b:02x}".upper() for b in bytes_addr)
    except Exception as e:
        logging.error(f"Error converting MAC address: {e}")
        return "00:00:00:00:00:00"

def get_ipv4(addr):
    try:
        return '.'.join(map(str, addr))
    except Exception as e:
        logging.error(f"Error converting IPv4 address: {e}")
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
        ip_proto = {
            '0x800': 'IPv4',
            '0x806': 'ARP',
            '0x86DD': 'IPv6'
        }.get(proto, proto)
        
        logging.debug(f"Source_MAC: {src_mac}\tDestination_MAC: {dest_mac}\nInternet Protocol: {ip_proto}")
        return eth_data, ip_proto
    except Exception as e:
        logging.error(f"Error parsing Ethernet frame: {e}")
        return None, None

def parse_packet(packet):
    try:
        first_byte = packet[0]
        ip_header_length = (first_byte & 15) * 4
        ttl, proto, src, dest = struct.unpack('!8xBB2x4s4s', packet[:20])
        
        src_ip = get_ipv4(src)
        dest_ip = get_ipv4(dest)
        
        transport_proto = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP'
        }.get(proto, f'Unknown Protocol Field = {proto}')
        
        logging.debug(f"Source_IP: {src_ip}\tDestination_IP: {dest_ip}\nTTL: {ttl} hops\tTransport_Protocol: {transport_proto}")
        return packet[ip_header_length:], transport_proto
    except Exception as e:
        logging.error(f"Error parsing IP packet: {e}")
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
        
        logging.debug(f"Type: {icmp_type}")
        return data[8:]
    except Exception as e:
        logging.error(f"Error parsing ICMP packet: {e}")
        return None

def parse_UDP(data):
    try:
        src_port, dest_port, packet_length = struct.unpack('!HHH', data[:6])
        logging.debug(f"Source_Port: {src_port}\tDestination_Port: {dest_port}\nPacket_Length: {packet_length}")
        return data[8:]
    except Exception as e:
        logging.error(f"Error parsing UDP packet: {e}")
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
        
        logging.debug(f"Source_Port: {src_port}\tDestination_Port: {dest_port}\nHeader_Length: {tcp_header_length}")
        logging.debug(f"Sequence: {seq}\nAcknowledgement: {ack}")
        logging.debug(f"Flags: URG ACK PSH RST SYN FIN\n      {flag_urg:3} {flag_ack:3} {flag_psh:3} {flag_rst:3} {flag_syn:3} {flag_fin:3}")
        return data[tcp_header_length:]
    except Exception as e:
        logging.error(f"Error parsing TCP packet: {e}")
        return None

def parse_transport_packet(data, protocol):
    try:
        if protocol == 'TCP':
            return parse_TCP(data)
        elif protocol == 'UDP':
            return parse_UDP(data)
        elif protocol == 'ICMP':
            return parse_ICMP(data)
    except Exception as e:
        logging.error(f"Error parsing transport packet: {e}")
        return None

def rev_dnslookup(ip_addr):
    try:
        ip_classes = [int(x) for x in ip_addr.split('.')]
        
        if ((ip_classes[0] == 10) or
            (ip_classes[0] == 172 and (16 <= ip_classes[1] <= 31)) or
            (ip_classes[0] == 192 and ip_classes[1] == 168)):
            logging.info(f'Private IP Address: {ip_addr}')
            return 'private_ip'
        else:
            try:
                rdns_data = socket.gethostbyaddr(ip_addr)
                logging.info(f"Domain Name: {rdns_data[0]}")
                logging.info(f"Host IP: {rdns_data[2][0]}")
                return rdns_data[0]
            except socket.error:
                logging.info("Domain Name not found.")
                return None
    except Exception as e:
        logging.error(f"Error in reverse DNS lookup: {e}")
        return None

def clear_console():
    os.system('clear')  # On Windows, use 'cls'

def main():
    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except socket.error as e:
        logging.error(f"Socket could not be created. Error: {e}")
        return

    packet_count = Counter()
    start_time = time.time()

    try:
        while True:
            try:
                payload, addr = conn.recvfrom(65535)
                ip_packet, ip_protocol = parse_frame(payload)
                if ip_protocol == 'IPv4':
                    packet_count['IPv4'] += 1
                    transport_packet, transport_proto = parse_packet(ip_packet)
                    if transport_packet and transport_proto:
                        packet_count[transport_proto] += 1
                        parse_transport_packet(transport_packet, transport_proto)

                if time.time() - start_time > 10:
                    start_time = time.time()
                    clear_console()
                    table = PrettyTable(['Protocol', 'Packet Count'])
                    for protocol, count in packet_count.items():
                        table.add_row([protocol, count])
                    print(colored('\nPacket Statistics (Last 10 seconds):', 'magenta'))
                    print(table)

            except Exception as e:
                logging.error(f"Error receiving or processing packet: {e}")

    except KeyboardInterrupt:
        print("\n\n\nStopped!!!")
    finally:
        conn.close()

if __name__ == "__main__":
    main()


