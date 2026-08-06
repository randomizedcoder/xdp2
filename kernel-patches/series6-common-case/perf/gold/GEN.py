import os, struct
from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap
R="/home/das/Downloads/xdp2"; GOLD=f"{R}/kernel-patches/series6-common-case/perf/gold"
os.makedirs(GOLD, exist_ok=True)

def inner(i, l4="tcp"):
    s=f"10.{i}.0.1"; d=f"10.{i}.0.2"; sp=1000+i; dp=80
    ip = IP(src=s, dst=d)/(TCP(sport=sp,dport=dp) if l4=="tcp" else UDP(sport=sp,dport=dp))
    proto = 6 if l4=="tcp" else 17
    return ip, f"{s},{d},{proto},{sp},{dp}"

def mpls_hdr(label=100, ttl=64):   # 4B, BoS=1
    v=(label<<12)|(1<<8)|ttl; return struct.pack(">I", v)
def pppoe_hdr(sid, plen):          # 6B PPPoE + 2B PPP proto (0x0021 IP)
    return bytes([0x11,0x00])+struct.pack(">H",sid)+struct.pack(">H",plen)+bytes([0x00,0x21])
def vxlan_hdr(vni): return bytes([0x08,0,0,0])+struct.pack(">I",vni<<8)  # flags I=1 + VNI(3)+rsvd
def geneve_hdr(vni): return bytes([0x00,0x00,0x65,0x58])+struct.pack(">I",vni<<8)  # ver0/optlen0, proto=TEB
def gtpu_hdr(teid,plen): return bytes([0x30,0xFF])+struct.pack(">H",plen)+struct.pack(">I",teid)  # v1,PT,type=G-PDU
def gue_hdr(): return bytes([0x00,0x04,0x00,0x00])  # ver0, proto_ctype=IPPROTO_IPIP -> inner IPv4

def build(shape):
    pkts=[]; rows=[]
    for i in range(1,9):
        ip,tup = inner(i)
        ib = bytes(ip)
        if shape=="mpls":   p=Ether(type=0x8847)/Raw(mpls_hdr()+ib)
        elif shape=="pppoe":p=Ether(type=0x8864)/Raw(pppoe_hdr(i,len(ib)+2)+ib)
        elif shape=="vxlan":p=Ether()/IP(src="192.0.2.1",dst="192.0.2.2")/UDP(sport=40000+i,dport=4789)/Raw(vxlan_hdr(i)+bytes(Ether()/ip))
        elif shape=="geneve":p=Ether()/IP(src="192.0.2.1",dst="192.0.2.2")/UDP(sport=40000+i,dport=6081)/Raw(geneve_hdr(i)+bytes(Ether()/ip))
        elif shape=="gtpu": p=Ether()/IP(src="192.0.2.1",dst="192.0.2.2")/UDP(sport=40000+i,dport=2152)/Raw(gtpu_hdr(i,len(ib))+ib)
        elif shape=="gue":  p=Ether()/IP(src="192.0.2.1",dst="192.0.2.2")/UDP(sport=40000+i,dport=6080)/Raw(gue_hdr()+ib)
        elif shape=="fou":  p=Ether()/IP(src="192.0.2.3",dst="192.0.2.4")/UDP(sport=41000+i,dport=5555)/Raw(ib)
        pkts.append(p); rows.append(f"{i},{tup}")
    wrpcap(f"{R}/data/pcaps/flow-menu/{shape}.pcap", pkts)
    open(f"{GOLD}/{shape}.csv","w").write("\n".join(rows)+"\n")
    print(f"{shape:7s} {len(pkts)} pkts, gold e.g. {rows[0]}")

for s in ["mpls","pppoe","vxlan","geneve","gtpu","gue","fou"]: build(s)

# --- the five in-tree-oracle shapes, synthetic with known inners ---
from scapy.all import Dot1Q
try:
    from scapy.all import Dot1AD
except Exception:
    Dot1AD = None
from scapy.layers.inet import GRE

def build2(shape):
    pkts=[]; rows=[]
    for i in range(1,9):
        ip,tup = inner(i)
        if shape=="eth_ip": p=Ether()/ip
        elif shape=="vlan": p=Ether()/Dot1Q(vlan=i)/ip
        elif shape=="qinq":
            if Dot1AD is not None: p=Ether()/Dot1AD(vlan=i)/Dot1Q(vlan=i+1)/ip
            else: p=Ether(type=0x88a8)/Dot1Q(vlan=i,type=0x8100)/Dot1Q(vlan=i+1)/ip
        elif shape=="ipip": p=Ether()/IP(src="192.0.2.1",dst="192.0.2.2")/ip
        elif shape=="gre":  p=Ether()/IP(src="192.0.2.1",dst="192.0.2.2")/GRE()/ip
        pkts.append(p); rows.append(f"{i},{tup}")
    wrpcap(f"{R}/data/pcaps/flow-menu/{shape}.pcap", pkts)
    open(f"{GOLD}/{shape}.csv","w").write("\n".join(rows)+"\n")
    print(f"{shape:7s} {len(pkts)} pkts, gold e.g. {rows[0]}")

for s in ["eth_ip","vlan","qinq","ipip","gre"]: build2(s)
