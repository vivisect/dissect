import unittest
import dissect.bitlab as bitlab

class BitLabTest(unittest.TestCase):

    def test_bitlab_bits(self):

        self.assertEqual( len(list(bitlab.bits(b'ABC'))), 24 )

        bits = bitlab.BitStream(b'A', order='big')
        self.assertEqual( bits.cast(5), 8)
        self.assertEqual( bits.cast(3), 1)

        bits = bitlab.BitStream(b'A', order='little')
        self.assertEqual( bits.cast(5), 16)
        self.assertEqual( bits.cast(3), 2)
