import unittest
import dissect.bitlab as bitlab

class BitLabTest(unittest.TestCase):

    def test_bitlab_bits(self):

        self.assertEqual( len(list(bitlab.bits(b'ABC'))), 24 )

        bits = bitlab.bits(b'A')

        self.assertEqual( bitlab.cast(bits,5), 8)
        self.assertEqual( bitlab.cast(bits,3), 1)

