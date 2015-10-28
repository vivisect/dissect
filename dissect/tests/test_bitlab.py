import unittest
import dissect.bitlab as bitlab

class BitLabTest(unittest.TestCase):

    def test_bitlab_bits(self):

        self.assertEqual( len(list(bitlab.bits(b'ABC'))), 24 )

        bits = bitlab.bits(b'A')
        self.assertEqual( bitlab.cast(bits,5), 1)
        self.assertEqual( bitlab.cast(bits,3), 2)

        bits = bitlab.bits(b'A', reverse=True)
        self.assertEqual( bitlab.cast(bits,5), 2)
        self.assertEqual( bitlab.cast(bits,3), 4)