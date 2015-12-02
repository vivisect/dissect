import unittest

import dissect.formats.inet as ds_inet

ipv4bytes = b'\x45\x00\x14\x00\x42\x41\x00\x00\x30\x06\x57\x56\x01\x02\x03\x04\x05\x06\x07\x08'

class InetTest(unittest.TestCase):

    def test_inet_ipv4(self):
        ipv4 = ds_inet.IPv4()
        ipv4.vsParse(ipv4bytes)

        self.assertEqual( len(ipv4), 20 )

        self.assertEqual( repr(ipv4['proto']), 'TCP' )
        self.assertEqual( ipv4.veriphl, 0x45 )
        self.assertEqual( ipv4.ttl, 0x30 )
        self.assertEqual( repr(ipv4['srcaddr']), '1.2.3.4' )
        self.assertEqual( repr(ipv4['dstaddr']), '5.6.7.8' )

    def test_inet_icmp(self):
        icmp = ds_inet.ICMP()
        icmp.type = 3
        icmp.code = 4
        icmp.checksum = 0x0202

        self.assertEqual( icmp.vsEmit(), b'\x03\x04\x02\x02' )

