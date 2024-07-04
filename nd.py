from pylibpcap.pcap import sniff
import binascii
from pylibpcap import get_first_iface
from colors import * 

ishex = lambda s: all(c in '0123456789abcdefABCDEF' for c in s)
icmp6_types = {
    1: "Destination Unreachable",
    2: "Packet Too Big",
    3: "Time Exceeded",
    4: "Parameter Problem",
    128: "Echo Request",
    129: "Echo Reply",
    133: "Router Solicitation",
    134: "Router Advertisement",
    135: "Neighbor Solicitation",
    136: "Neighbor Advertisement",
    137: "Redirect Message",
    138: "Router Renumbering",
    141: "Inverse Neighbor Discovery Solicitation",
    142: "Inverse Neighbor Discovery Advertisement",
    143: "MLD (Multicast Listener Discovery) Listener Query",
    144: "MLD Listener Report",
    145: "MLD Listener Done",
    146: "Home Agent Address Discovery Request",
    147: "Home Agent Address Discovery Reply",
    148: "Mobile Prefix Solicitation",
    149: "Mobile Prefix Advertisement",
    151: "Certification Path Solicitation",
    152: "Certification Path Advertisement",
    153: "Experimental Mobility Protocols",
    200: "Private Experimentation",
    201: "Private Experimentation",
    255: "Reserved for expansion of ICMPv6 informational messages"
}


class ND:
    def __init__(self, raw=None):

        

        self.eth_dst = None  
        self.eth_src = None 
        self.eth_type = '86dd' 

        self.version = 6
        self.tclass = None
        self.ecn = None 
        self.dsc = None 
        self.label = None 

        self.plen = None 
        self.nexth = None 
        self.hop = None
        self.ip6_src = None 
        self.ip6_dst = None 


        self.icmp6_type = None 
        self.icmp6_code = None 
        self.icmp6_checksum = None 
        self.icmp6_resv= None 


        #Neighbor Solicitation
        self.nd_target = None  
        self.nd_opt_type = None 
        self.nd_opt_len = None 
        self.nd_opt_address = None 

        #Neighbor Advertisement
        self.nd_na_flags = None  
        self.nd_na_options = None  

        #Router Advertisement
        self.nd_ra_chl = None 
        self.nd_ra_mo = None 
        self.nd_ra_life = None 
        self.nd_ra_reachable = None 
        self.nd_ra_retrans = None 
        self.nd_ra_options = None 




        if raw is not None and isinstance(raw, (bytes)):
            self.dissect(binascii.hexlify(raw).decode())
        else:
            self.dissect(raw)
    
    def dissect(self,raw=None):
        print(f"{YELLOW}NDP{RESET}>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
        self.eth_dst = raw[0:12]
        self.eth_src = raw[12:24]
        self.eth_type = raw[24:28]

        self.version = raw[28:29]
        self.tclass = raw[29:31]
        self.label = raw[31:36]

        self.plen = int(raw[36:40],16) if ishex(raw[36:40]) else None 
        self.nexth = int(raw[40:42],16) if ishex(raw[40:42]) else -1  
        self.hop = int(raw[42:44],16) if ishex(raw[42:44]) else -1

        self.ip6_src = raw[44:76]
        self.ip6_dst = raw[76:108]

        if self.nexth != 58:
            return 
            
        self.icmp6(raw[108:])

    def icmp6(self, raw):
        #print("ICMP:",raw)
        self.icmp6_type = int(raw[0:2],16) if ishex(raw[0:2]) else None 
        self.icmp6_code = int(raw[2:4],16) if ishex(raw[2:4]) else None
        self.icmp6_checksum = raw[4:8]
        self.icmp6_resv = int(raw[8:16],16) if ishex(raw[8:16]) else None 

        # if not self.icmp6_type or not self.icmp6_code or not self.icmp6_resv:
        #     print("Protocol error!")
        #     return 

        if self.icmp6_type == 135:
            self.neighbor_solicitation(raw[16:])
        elif self.icmp6_type == 136:
            self.nd_na_flags = (self.icmp6_resv & 0xc0000000) >> 29
            self.icmp6_resv = self.icmp6_resv & 0x1fffffff
            self.neighbor_advertisement(raw[16:])
        elif self.icmp6_type == 134:
            self.nd_ra_chl = (self.icmp6_resv & 0xff000000) >> 24 
            self.nd_ra_mo = (self.icmp6_resv & 0x00c00000) >> 22  
            self.nd_ra_life = (self.icmp6_resv & 0x0000ffff) 
            self.icmp6_resv = (self.icmp6_resv & 0x0003f0000) >> 16
            self.router_advertisement(raw[16:])
      

        else:
            print(self.icmp6_type, f"{RED}=>STILL UNKNOWN{RESET}")

    def router_advertisement(self, raw):

        self.nd_ra_reachable = int(raw[0:32],16) if ishex(raw[0:32]) else None 
        self.nd_ra_retrans = int(raw[32:64],16) if ishex(raw[32:64]) else None
        if len(raw[64:]) > 0:
            self.nd_ra_options = raw[64:]

    def neighbor_solicitation(self, raw):
        self.nd_target = raw[0:32]
        if len(raw[32:]) > 0:
            self.nd_opt_type = int(raw[32:34]) if ishex(raw[32:34]) else None 
            self.nd_opt_len = int(raw[34:36]) if ishex(raw[34:36]) else None 
            self.nd_opt_address = raw[36:]

    def neighbor_advertisement(self, raw):
        self.nd_target = raw[0:32]
        if len(raw[32:]) > 0:
            self.nd_na_options = raw[32:]


    def pretty(self):
        print('[e] dst    :',self.eth_dst) 
        print('[e] src    :',self.eth_src) 
        print('[e] type   :',self.eth_type) 

        print('[ip6] version   :',self.version)
        print('[ip6] class     :', self.tclass)
        print('[ip6] label     :',self.label)
        print('[ip6] plen      :',self.plen)
        print('[ip6] nexth     :',self.nexth)
        print('[ip6] hlim      :',self.hop)
        print('[ip6] ip6_src   :',self.ip6_src)
        print('[ip6] ip6_dst   :',self.ip6_dst)

        if self.nexth != 58:
            print('Unknown protocol!')
            return 

        print("[icmp6] type     :",self.icmp6_type,f"({BLUE}{icmp6_types[self.icmp6_type]}{RESET})")
        print('[icmp6] code     :',self.icmp6_code)
        print('[icmp6] checksum :',self.icmp6_checksum)
        print('[icmp6] reserve  :',self.icmp6_resv)

        if self.icmp6_type == 135:
            print('[nd] target  :',self.nd_target)
            print('[nd] type    :',self.nd_opt_type) if self.nd_opt_type else None 
            print('[nd] len     :',self.nd_opt_len) if self.nd_opt_len else None 
            print('[nd] addr    :',self.nd_opt_address) if self.nd_opt_address else None 
        elif self.icmp6_type == 136:
            print('[nd] RSO     :',self.nd_na_flags, f"({bin(self.nd_na_flags)[2:].zfill(3)})")
            print('[nd] target  :',self.nd_target)
            print('[nd] options :',self.nd_na_options) if self.nd_na_options else None
        elif self.icmp6_type == 134:
            #print(f"{RED}NEW{RESET}")
            print('[nd] CHL   :',self.nd_ra_chl)
            print('[nd] mo    :',self.nd_ra_mo)
            print('[nd] life  :',self.nd_ra_life)
            print('[nd] reach :',self.nd_ra_reachable)
            print('[nd] retr  :',self.nd_ra_retrans)
            print('[nd] options :',self.nd_ra_options) if self.nd_ra_options else None 

            
if __name__ == '__main__':
    dev=get_first_iface()
    print("Capture: ",dev)
    nd = ND("748f3cc24b0d60f18a36814686dd6000000000183afffe800000000000000000000000000001fe800000000000001c9e716ca96df65388008e5bc0000000fe800000000000000000000000000001")
    nd.pretty()
    for plen, t, buf in sniff(dev, count=100, promisc=1, filters="icmp6"):
        if buf is not None and isinstance(buf, (bytes)):
            #print(binascii.hexlify(buf).decode())
            nd = ND(buf)
            nd.pretty()