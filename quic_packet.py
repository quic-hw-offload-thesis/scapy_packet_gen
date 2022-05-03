from scapy.fields import BitEnumField, BitField, BitFieldLenField, StrField
from scapy.packet import Packet

from scapy.fields import *

# SOURCE: E. Gagliardi and O. Levillain, “Analysis of quic session establishment and its implementations,” in IFIP International Conference on Information Security Theory and Practice. Springer, 2019, pp. 169–184.
# DOCS: https://scapy.readthedocs.io/en/latest/build_dissect.html#
# SOURCE: https://www.rfc-editor.org/rfc/rfc9000.html#name-1-rtt-packet


class QUIC(Packet):
    # INFO: Only short headers are supported
    name = "QUIC"
    fields_desc = [
        # Flags
        BitEnumField("hdr_form", 0, 1, {0: "0 (short)", 1: "(long)"}),
        BitEnumField("fixed_bit", 1, 1, {0: "0 (error)", 1: "1 (ok)"}),
        BitEnumField("spin_bit", 1, 1, {0: "0", 1: "1"}),
        BitField("reserved", 0, 2),
        BitEnumField("key_phase", 0, 1, {0: "0", 1: "1"}),
        BitFieldLenField("pnr_len", None, 2, length_of="packet_nr"),
        StrField("dcid", None),
        StrLenField("packet_nr", 0, lambda pkt: pkt.packet_nr_len + 1)
    ]
