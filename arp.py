import binascii
from colors import * 

opcodes = {
    1: "ARP Request",
    2: "ARP Reply"
}


class ARP:
    def __init__(self, raw=None):

        self.eth_dst = 'ffffffffffff' 
        self.eth_src = None 
        self.eth_type = '0806' 

        self.hw = '0001'
        self.proto = '0800'
        self.hw_len= '06'
        self.ip_len= '04'
        self.opcode = '0001'
        self.src_hw = None
        self.src_ip = None
        self.dst_hw = '000000000000'  
        self.dst_ip = None

        if raw is not None and isinstance(raw, (bytes)):
            self.dissect(binascii.hexlify(raw).decode())

    def dissect(self, raw):
        #print(raw)
        # ffffffffffff
        # 00a38e7e237d
        # 0806
        self.eth_dst = raw[0:12]
        self.eth_src = raw[12:24]
        self.eth_type = raw[24:28]
        # 0001
        # 0800
        # 06
        # 04
        self.hw     =   raw[28:32]
        self.proto  =   raw[32:36]
        self.hw_len =   raw[36:38]
        self.ip_len =   raw[38:40]
        # 0001
        # 00a38e7e237d
        # c0a802fe
        # 000000000000
        # c0a8028b
        self.opcode = raw[40:44]
        self.src_hw = raw[44:56]
        self.src_ip = raw[56:64]
        self.dst_hw = raw[64:76]
        self.dst_ip = raw[76:84]
    
    def set_src_hw(self,hw):
        if ":" in hw:
            hw = hw.replace(":","")
        self.eth_src = hw
        self.src_hw = hw
        
    def set_src_ip(self, ip):
        self.src_ip = self.iphex(ip)

    def set_opt(self,opt):
        if isinstance(opt, (int)):
            opt = str(opt)
        opt = opt.rjust(4,"0")
        self.opcode = opt
    def set_dst_hw(self, hw):
        if ":" in hw:
            hw = hw.replace(":","")
        self.dst_hw = hw
        self.eth_dst = hw
    def set_dst_ip(self,ip):
        self.dst_ip = self.iphex(ip)

    def pretty(self):
        print(f"{RED}ARP{RESET}>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
        print('[e] dst    :',self.eth_dst) 
        print('[e] src    :',self.eth_src) 
        print('[e] type   :',self.eth_type) 
        print('[a] hw     :',self.hw) 
        print('[a] proto  :',self.proto) 
        print('[a] hw_len :',self.hw_len) 
        print('[a] ip_len :',self.ip_len) 
        print('[a] opt    :',self.opcode, f"({BLUE}{opcodes[int(self.opcode,16)]}{RESET})") 
        print('[a] src_hw :',self.src_hw) 
        print('[a] src_ip :',self.ip(self.src_ip)) 
        print('[a] dst_hw :',self.dst_hw) 
        print('[a] dst_ip :',self.ip(self.dst_ip)) 

        #print('-')
    def get(self):
        raw = binascii.unhexlify(
            self.eth_dst+
            self.eth_src+
            self.eth_type+
            self.hw+
            self.proto+
            self.hw_len+
            self.ip_len+
            self.opcode+
            self.src_hw+
            self.src_ip+
            self.dst_hw+
            self.dst_ip
        )
        #print(raw)
        return raw

    def iphex(self,ip):
        hx = ''
        for i in ip.split('.'):
            hx=hx+hex(int(i))[2:].rjust(2,'0')
        return hx

    def ip(self,ip):
        if ip is None:
            return ""
        a = int(ip[0:2],16)
        b = int(ip[2:4],16)
        c = int(ip[4:6],16)
        d = int(ip[6:8],16)
        return str(a)+"."+str(b)+"."+str(c)+"."+str(d)
