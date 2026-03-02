import scapy.all as scapy

INSIDE_IFACE = "enp0s8"
OUTSIDE_IFACE = "enp0s9"
OUTSIDE_PROXY_IP = "192.168.218.1"
INSIDE_PROXY_IP = "192.168.163.1" 
TO_HIDE_IP = "10.10.10.10"

def send_inside_packet(recieved):
    """Sends packets from the inner subnet to the internet."""
    to_send = scapy.IP(src=OUTSIDE_PROXY_IP, dst=recieved[scapy.IP].dst, ttl=64) / recieved[scapy.IP].payload
    del to_send[scapy.IP].chksum
    del to_send[scapy.IP].len
    scapy.send(to_send, iface=OUTSIDE_IFACE)

def send_outside_packet(recieved): 
    """Sends packets from the internet to the inner subnet."""
    to_send = scapy.IP(src=INSIDE_PROXY_IP, dst=TO_HIDE_IP, ttl=64) / recieved[scapy.IP].payload
    del to_send[scapy.IP].chksum
    del to_send[scapy.IP].len
    scapy.send(to_send, iface=INSIDE_IFACE)

def main():
    inside_sniffer = scapy.AsyncSniffer(iface=INSIDE_IFACE, store=False, filter="ip and inbound", prn=send_inside_packet)
    outside_sniffer = scapy.AsyncSniffer(iface=INSIDE_IFACE, store=False, filter="ip and inbound", prn=send_outside_packet)
    inside_sniffer.start()
    outside_sniffer.start()
    input("Press enter to exit")

if __name__ == "__main__":
    main()