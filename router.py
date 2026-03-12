import scapy.all as scapy

IFACE_1 = "enp0s8"
IFACE_2 = "enp0s9"
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
    scapy.sendp(scapy.Ether() / packet[scapy.IP], iface=to_send_iface, verbose=True)

def main():
    scapy.sniff(iface=[IFACE_1, IFACE_2, "enp0s3"], prn=route_packet, store=False, filter="inbound")

if __name__ == "__main__":
    main()