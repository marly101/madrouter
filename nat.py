import scapy.all as scapy
from FourTuple import FourTuple
from Session import Session
import random

INSIDE_IFACE = "enp0s8"
OUTSIDE_IFACE = "enp0s9"
OUTSIDE_PROXY_IP = "192.168.218.1"
INSIDE_PROXY_IP = "192.168.163.1" 
ICMP_UNREACHABLE_TYPE = 3
ICMP_HOST_UNREACHABLE_CODE = 1
MINIMUM_SESSION_PORT = 5517
MAXIMUM_SESSION_PORT = 65532
fourtuple_to_session_dict = {}
session_to_fourtuple_dict = {}



def create_session(four_tuple):
    session_port = random.randint(MINIMUM_SESSION_PORT, MAXIMUM_SESSION_PORT)
    session = Session(session_port, four_tuple.proto)
    while session in session_to_fourtuple_dict:
        session_port = random.randint(MINIMUM_SESSION_PORT, MAXIMUM_SESSION_PORT)
        session = Session(session_port, four_tuple.proto)
    fourtuple_to_session_dict[four_tuple] = session
    session_to_fourtuple_dict[session] = four_tuple

def exctract_four_tuple(packet):
    if packet.haslayer(scapy.TCP):
        return FourTuple(packet.src, packet.sport, packet.dst, packet.dport, scapy.TCP)
    elif packet.haslayer(scapy.UDP):
        return FourTuple(packet.src, packet.sport, packet.dst, packet.dport, scapy.UDP)
    return 

def send_inside_packet(packet):
    packet_four_tuple = exctract_four_tuple(packet)
    if not packet_four_tuple in fourtuple_to_session_dict:
        create_session(packet_four_tuple)
    packet.sport = fourtuple_to_session_dict[packet_four_tuple].port
    packet[scapy.IP].src = OUTSIDE_PROXY_IP
    del packet.ttl
    del packet.chksum
    scapy.sendp(scapy.Ether() / packet[scapy.IP], iface=OUTSIDE_IFACE)

def send_outside_packet(packet):
    if packet.haslayer(scapy.TCP):
        packet_proto = scapy.TCP
    elif packet.haslayer(scapy.UDP):
        packet_proto = scapy.UDP
    else:
        return
    packet_session = Session(packet.dport, packet_proto)
    if not packet_session in session_to_fourtuple_dict:
        scapy.send(scapy.IP(dst=packet[scapy.IP].src) 
                    / scapy.ICMP(type=ICMP_UNREACHABLE_TYPE, code=ICMP_HOST_UNREACHABLE_CODE))
        return
    packet_four_tuple = session_to_fourtuple_dict[packet_session]
    packet[scapy.IP].src = packet_four_tuple.external_ip
    packet[scapy.IP].dst = packet_four_tuple.internal_ip
    packet.sport = packet_four_tuple.external_port
    packet.dport = packet_four_tuple.internal_port
    del packet.ttl
    del packet.chksum
    scapy.sendp(scapy.Ether() / packet[scapy.IP], iface=OUTSIDE_IFACE)

def main():
    inside_sniffer = scapy.AsyncSniffer(iface=INSIDE_IFACE, store=False, filter="ip and (tcp or udp) and inbound", prn=send_inside_packet)
    outside_sniffer = scapy.AsyncSniffer(iface=OUTSIDE_IFACE, store=False, filter="ip and (tcp or udp) and inbound", prn=send_outside_packet)
    inside_sniffer.start()
    outside_sniffer.start()
    input("Press enter to exit")

if __name__ == "__main__":
    main()
