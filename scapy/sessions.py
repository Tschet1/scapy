# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
Sessions: decode flow of packets when sniffing
"""

from collections import defaultdict
from scapy.compat import raw
from scapy.plist import PacketList, KeyOrderedDict


class DefaultSession(object):
    """Default session: no stream decoding"""

    def __init__(self, prn, store):
        self.prn = prn
        self.store = store
        self.lst = []

    def toPacketList(self):
        return PacketList(self.lst, "Sniffed")

    def on_packet_received(self, pkt):
        """DEV: entry point. Will be called by sniff() for each
        received packet (that passes the filters).
        """
        if not pkt:
            return
        if isinstance(pkt, list):
            for p in pkt:
                DefaultSession.on_packet_received(self, p)
            return
        if self.store:
            self.lst.append(pkt)
        if self.prn:
            result = self.prn(pkt)
            if result is not None:
                print(result)


class IPSession(DefaultSession):
    """Defragment IP packets 'on-the-flow'.
    Usage:
      >>> sniff(session=IPSession)
    """

    def __init__(self, *args):
        DefaultSession.__init__(self, *args)
        self.fragments = defaultdict(list)

    def _ip_process_packet(self, packet):
        from scapy.layers.inet import _defrag_list, IP
        if IP not in packet:
            return packet
        ip = packet[IP]
        packet._defrag_pos = 0
        if ip.frag != 0 or ip.flags.MF:
            uniq = (ip.id, ip.src, ip.dst, ip.proto)
            self.fragments[uniq].append(packet)
            if not ip.flags.MF:  # end of frag
                try:
                    if self.fragments[uniq][0].frag == 0:
                        # Has first fragment (otherwise ignore)
                        defrag, missfrag = [], []
                        _defrag_list(self.fragments[uniq], defrag, missfrag)
                        defragmented_packet = defrag[0]
                        defragmented_packet = defragmented_packet.__class__(
                            raw(defragmented_packet)
                        )
                        return defragmented_packet
                finally:
                    del self.fragments[uniq]
        else:
            return packet

    def on_packet_received(self, pkt):
        pkt = self._ip_process_packet(pkt)
        DefaultSession.on_packet_received(self, pkt)


class TCPSession(IPSession):
    """A Session that matches seq/ack packets together to dissect
    special protocols, such as HTTP.

    DEV: implement a class-function `tcp_reassemble` in your Packet class:
        @classmethod
        def tcp_reassemble(cls, frags, metadata):
            # frags = the fragments that come from the same request/flow
            # metadata = empty dictionary, that can be used to store data
            [...]
            # If the packet is available, return it (you may want to delete
            # existing fragments in frags that were used to build it)
            return pkt
            # Otherwise, maybe store stuff in metadata, and return None,
            # as you need more fragments to build the packet.
            return None

    A (hard to understand) example can be found in scapy/layers/http.py
    """

    def __init__(self, *args):
        IPSession.__init__(self, *args)
        # A classic dictionary is unpredictable depending on the Python
        # version. Let's use our custom KeyOrderedDict instead
        self.tcp_frags = defaultdict(
            lambda: defaultdict(lambda: (KeyOrderedDict(), {}))
        )

    def _process_packet(self, pkt):
        from scapy.layers.inet import TCP
        if TCP not in pkt:
            return pkt
        pay = pkt[TCP].payload
        fmt = ('TCP {IP:%IP.src%}{IPv6:%IPv6.src%}:%r,TCP.sport% > ' +
               '{IP:%IP.dst%}{IPv6:%IPv6.dst%}:%r,TCP.dport%')
        ack_fmt = ('TCP {IP:%IP.dst%}{IPv6:%IPv6.dst%}:%r,TCP.dport% > ' +
                   '{IP:%IP.src%}{IPv6:%IPv6.src%}:%r,TCP.sport%')
        ident = pkt.sprintf(fmt)
        ack = pkt.sprintf(ack_fmt)
        seq = pkt[TCP].seq
        if "pay_class" not in self.tcp_frags[ident][ack][1]:
            pay_class = pay.__class__
            if not hasattr(pay_class, "tcp_reassemble"):
                # Cannot tcp-reassemble
                return pkt
            self.tcp_frags[ident][ack][1]["pay_class"] = pay_class
        else:
            pay_class = self.tcp_frags[ident][ack][1]["pay_class"]
        self.tcp_frags[ident][ack][0][seq] = pkt
        # Reassemble using all previous packets
        return pay_class.tcp_reassemble(*self.tcp_frags[ident][ack])

    def on_packet_received(self, pkt):
        # First, defragment IP if necessary
        pkt = self._ip_process_packet(pkt)
        # Now handle TCP reassembly
        pkt = self._process_packet(pkt)
        DefaultSession.on_packet_received(self, pkt)
