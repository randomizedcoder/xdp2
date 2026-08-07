from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap
# Fixed OUTER 5-tuple (one VTEP pair, fixed outer UDP sport) — the reordering
# scenario: without descent every packet hashes identically. VARYING inner flows.
def vxh(vni): return bytes([0x08,0,0,0]) + (vni<<8).to_bytes(4,"big")
pkts=[]
N=1000
for i in range(N):
    inner = Ether()/IP(src=f"10.{(i>>8)&0xff}.{i&0xff}.1",
                       dst=f"10.{(i>>8)&0xff}.{i&0xff}.2")/TCP(sport=1024+(i%50000),dport=80)
    p = Ether(dst="f8:f2:1e:38:ab:80")/IP(src="192.0.2.1",dst="192.0.2.2")/UDP(sport=12345,dport=4789)/Raw(vxh(100)+bytes(inner))
    pkts.append(p)
wrpcap("/tmp/vxlan-demo.pcap", pkts)
print(f"wrote /tmp/vxlan-demo.pcap : {N} pkts, fixed outer 192.0.2.1:12345->192.0.2.2:4789, {N} distinct inner flows")
