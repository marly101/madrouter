import scapy.all as scapy

OUTSIDE_IFACE = "enp0s8"
INSIDE_IFACE = "enp0s9"
BLOCKED_PORT = 12345
ICMP_UNREACHABLE_TYPE = 3
ICMP_HOST_UNREACHABLE_CODE = 1
ICMP_TIME_EXCEEDED_TYPE = 11
ICMP_TTL_EXPIRED_CODE = 0
LOOPBACK = "lo"

def route_packet(packet):
    if not packet.haslayer(scapy.IP):
        return
    packet[scapy.IP].ttl -= 1
    if packet[scapy.IP].ttl <= 0:
        scapy.send(scapy.IP(dst=packet[scapy.IP].src) 
                    / scapy.ICMP(type=ICMP_TIME_EXCEEDED_TYPE, code=ICMP_TTL_EXPIRED_CODE))
        return
    to_send_iface = scapy.conf.route.route(packet[scapy.IP].dst)[0]
    # Send ICMP unreachable if dst IP isn't in routing table
    if to_send_iface == LOOPBACK:
        print(scapy.IP(dst=packet[scapy.IP].src) 
                    / scapy.ICMP(type=ICMP_UNREACHABLE_TYPE, code=ICMP_HOST_UNREACHABLE_CODE))
        scapy.send(scapy.IP(dst=packet[scapy.IP].src) 
                    / scapy.ICMP(type=ICMP_UNREACHABLE_TYPE, code=ICMP_HOST_UNREACHABLE_CODE))
        return
    print(scapy.Ether() / packet[scapy.IP])
    print(to_send_iface)
    if packet.sniffed_on == OUTSIDE_IFACE and packet.haslayer(scapy.UDP) and packet.sport == BLOCKED_PORT:
        return
    scapy.sendp(scapy.Ether() / packet[scapy.IP], iface=to_send_iface, verbose=True)


def main():
    scapy.sniff(iface=[OUTSIDE_IFACE, INSIDE_IFACE], prn=route_packet, store=False, filter="inbound")

if __name__ == "__main__":
    main()