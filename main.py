from pylibpcap import get_iface_list, get_first_iface
from pylibpcap.pcap import sniff
import ifcfg
import binascii
from arp import ARP 
from nd import ND 

if __name__ == '__main__':
    #signal.signal(signal.SIGINT, sigint_handler)
    default = ifcfg.default_interface()
    device = str(default['device'])
    for plen, t, buf in sniff(device, count=10, promisc=1, filters="arp or icmp6"):
        if buf is not None and isinstance(buf, (bytes)):
            eth = binascii.hexlify(buf).decode()[:28]
            print(eth[24:28])
            if '86dd' in eth[24:28]:
                nd = ND(buf)
                nd.pretty()
            elif '0806' in eth[24:28]:
                arp = ARP(buf)
                arp.pretty()