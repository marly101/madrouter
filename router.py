import scapy.all as scapy
import socket
import select

RECV_IFACE = "enp0s8"
SEND_IFACE = "enp0s9"
RECV_SIZE = 1500
ETH_P_ALL = 3
ETH_P_IP = 0x800

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
s.bind((RECV_IFACE, 0))
sock_select = select.select([s], [], [])
while True:
    for sock in sock_select[0]:
        recieved = sock.recv(RECV_SIZE)
        scapy.sendp(recieved, iface=SEND_IFACE)
