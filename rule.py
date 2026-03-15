import scapy.all as scapy

MAC_SRC_ADDRESS = "MAC_SRC_ADDRESS"
MAC_DST_ADDRESS = "MAC_DST_ADDRESS"
IP_SRC_ADDRESS = "IP_SRC_ADDRESS"
IP_DST_ADDRESS = "IP_DST_ADDRESS"
UDP_DPORT = "UDP_DPORT"
TCP_DPORT = "TCP_DPORT"
UDP_SPORT = "UDP_SPORT"
TCP_SPORT = "TCP_SPORT"


class Rule:
    
    rule_types = [MAC_SRC_ADDRESS, 
                  MAC_DST_ADDRESS, 
                  IP_SRC_ADDRESS,
                  IP_DST_ADDRESS,
                  UDP_DPORT, 
                  TCP_DPORT,
                  UDP_SPORT,
                  TCP_SPORT] 

    def __init__(self, type, blocked_instance):
            if(type not in self.rule_types):
                print("Not a valid rule type!")
                return
            self.type = type
            self.blocked_instance = blocked_instance
    
    def filter(self, packet):
        if self.type == MAC_SRC_ADDRESS:
            return False if packet[scapy.Ether].src == self.blocked_instance else True 
        elif self.type == MAC_DST_ADDRESS:
            return False if packet[scapy.Ether].dst == self.blocked_instance else True
        elif self.type == IP_SRC_ADDRESS: 
            if not packet.haslayer(scapy.IP):
                return True
            else:
                return False if packet[scapy.IP].src == self.blocked_instance else True
        elif self.type == IP_DST_ADDRESS: 
            if not packet.haslayer(scapy.IP):
                return True
            else:
                return False if packet[scapy.IP].dst == self.blocked_instance else True 
        elif self.type == UDP_SPORT: 
            if not packet.haslayer(scapy.UDP):
                return True
            else:
                return False if packet[scapy.UDP].sport == self.blocked_instance else True 
        elif self.type == UDP_DPORT: 
            if not packet.haslayer(scapy.UDP):
                return True
            else:
                return False if packet[scapy.UDP].dport == self.blocked_instance else True
        elif self.type == TCP_SPORT: 
            if not packet.haslayer(scapy.TCP):
                return True
            else:
                return False if packet[scapy.TCP].sport == self.blocked_instance else True   
        elif self.type == TCP_DPORT: 
            if not packet.haslayer(scapy.TCP):
                return True
            else:
                return False if packet[scapy.TCP].dport == self.blocked_instance else True            
        return True