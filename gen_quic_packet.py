from scapy.all import Packet, Ether, IP, UDP, wireshark, hexdump
from quic_packet import QUIC

# Define packet fields
ETH_DEST_MAC = "de:fa:ce:db:ab:e1"
ETH_SRC_MAC = "38:de:ad:64:16:62"
ETH_PROTO = 0x0800

IP_VER = 4
IP_IHL = 0x5
IP_SRC_ADDR = "10.25.135.108"
IP_DEST_ADDR = "172.64.146.82"

UDP_SRC_PORT = 63968
# INFO: Set quic port in wireshark settings in order to decode (Edit > Preferences > Protocols > QUIC > QUIC UDP PORT)
UDP_DEST_PORT = 12345

QUIC_SPIN_BIT = 1
QUIC_RESERVED = 0
QUIC_KEY_PHASE = 0
QUIC_PACKET_NR_LEN = 3
QUIC_DCID = b'\x01\x98\x65\x84\x6a\x13\x07\x8e\x74\x98\x2b\x84\x75\x13\x1b\x04\x83\x4d\xd8\x4f'
QUIC_PACKET_NR = (13021385).to_bytes(QUIC_PACKET_NR_LEN, 'big')

# SOURCE: https://scapy.readthedocs.io/en/latest/
pkt: Packet = \
    Ether(dst=ETH_DEST_MAC, src=ETH_SRC_MAC, type=ETH_PROTO) / \
    IP(version=IP_VER, ihl=IP_IHL, src=IP_SRC_ADDR, dst=IP_DEST_ADDR) / \
    UDP(sport=UDP_SRC_PORT, dport=UDP_DEST_PORT) / \
    QUIC(pnr_len=QUIC_PACKET_NR_LEN, dcid=QUIC_DCID,
         packet_nr=QUIC_PACKET_NR, spin_bit=QUIC_SPIN_BIT,
         reserved=QUIC_RESERVED, key_phase=QUIC_KEY_PHASE)

pkt.add_payload(b"\x54\x02\x9b\xa8\xe9\xe6\xc1\x28\x7d\x65\x53\x06\x6a\x5d\x24\xee\x6e\xd5\xe7\x41\x34\xca\x73\x1e\x32\x53\xf2\xeb\x90\x65\xaf\x5e\x2e\x44\x5d\x47\x2f\xd3\xbe\xa4\xd1\x97\xa5\x06\x8e\xf6\x18\xd7\x89\x56\xc8\x59\xe5\x0d\x50\x9b")

pkt.show()
pkt.show2()
hexdump(pkt)

wireshark(pkt)
