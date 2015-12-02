import socket

from vstruct.types import *

'''
Inet Packet Structures
'''

ethp = venum()
ethp.ipv4 = 0x0800
ethp.ipv6 = 0x86dd
ethp.vlan = 0x8100

ipproto = venum()
ipproto.ICMP    = 1
ipproto.TCP     = 6
ipproto.UDP     = 17
ipproto.IPV6    = 41

TCP_F_FIN  = 0x01
TCP_F_SYN  = 0x02
TCP_F_RST  = 0x04
TCP_F_PUSH = 0x08
TCP_F_ACK  = 0x10
TCP_F_URG  = 0x20
TCP_F_ECE  = 0x40
TCP_F_CWR  = 0x80

# Useful combinations...
TCP_F_SYNACK = (TCP_F_SYN | TCP_F_ACK)

icmptypes = venum()
icmptypes.ECHOREPLY        =  0
icmptypes.DEST_UNREACH     =  3
icmptypes.SOURCE_QUENCH    =  4
icmptypes.REDIRECT         =  5
icmptypes.ECHO             =  8
icmptypes.TIME_EXCEEDED    = 11
icmptypes.PARAMETERPROB    = 12
icmptypes.TIMESTAMP        = 13
icmptypes.TIMESTAMPREPLY   = 14
icmptypes.INFO_REQUEST     = 15
icmptypes.INFO_REPLY       = 16
icmptypes.ADDRESS          = 17
icmptypes.ADDRESSREPLY     = 18

class IPv4Addr(uint32):

    def __repr__(self):
        return socket.inet_ntop(socket.AF_INET, bytes(self))

class IPv6Addr(vbytes):

    def __init__(self):
        vbytes.__init__(self, size=16)

    def __repr__(self):
        return socket.inet_ntop(socket.AF_INET6, self._vs_value)

class ETHERII(VStruct):
    def __init__(self):
        VStruct.__init__(self)
        self._vs_endian = 'big'
        self.destmac    = vbytes(size=6)
        self.srcmac     = vbytes(size=6)
        self.etype      = uint16(enum=ethp)

        self['etype'].vsOnset( self._onSetEtype )

    def _onSetEtype(self):
        # append vlan tags if needed
        if etype == ethp.vlan:
            self.vtag = uint16()
            self.vvlan = uint16()

class IPv4(VStruct):
    def __init__(self):
        VStruct.__init__(self)
        self._vs_endian = 'big'
        self.veriphl    = uint8()
        self.tos        = uint8()
        self.totlen     = uint16()
        self.ipid       = uint16()
        self.flagfrag   = uint16()
        self.ttl        = uint8()
        self.proto      = uint8(enum=ipproto)
        self.cksum      = uint16()
        self.srcaddr    = IPv4Addr()
        self.dstaddr    = IPv4Addr()

        self['veriphl'].vsOnset( self._onSetVerIphl )

    def _onSetVerIphl(self):
        iphl = (self.veriphl & 0xf) * 4
        if iphl > 20:
            self.ipopts = vbytes( iphl - 20 )

class IPv6(VStruct):
    def __init__(self):
        VStruct.__init__(self)
        self._vs_endian = 'big'
        self.verclsflowl= uint32()
        self.totlen     = uint16()
        self.nexthdr    = uint8()
        self.hoplimit   = uint8()
        self.srcaddr    = IPv6Addr()
        self.dstaddr    = IPv6Addr()

class TCP(VStruct):

    def __init__(self):
        VStruct.__init__(self)
        self._vs_endian = 'big'
        self.srcport    = uint16()
        self.dstport    = uint16()
        self.sequence   = uint32()
        self.ackseq     = uint32()
        self.doff       = uint8()
        self.flags      = uint8()
        self.window     = uint16()
        self.checksum   = uint16()
        self.urgent     = uint16()

        self['doff'].vsOnset( self._onSetDoff )

    def _onSetDoff(self):
        off = (self.doff >> 2)
        if off >= 20:
            self.tcpopts = vbytes( off - 20 )

class UDP(VStruct):
    def __init__(self):
        VStruct.__init__(self)
        self._vs_endian = 'big'
        self.srcport    = uint16()
        self.dstport    = uint16()
        self.udplen     = uint16()
        self.checksum   = uint16()

class ICMP(VStruct):
    def __init__(self):
        VStruct.__init__(self)
        self._vs_endian = 'big'
        self.type       = uint8(enum=icmptypes)
        self.code       = uint8()
        self.checksum   = uint16()
