import unittest

import dissect.bitlab as bitlab
import dissect.algos.huffman as huffman

huffbook = ( (0, 3, 2), (1, 3, 3), (2, 3, 4), (3, 3, 5), (4, 3, 6), (5, 2, 0), (6, 4, 14), (7, 4, 15) )
huffsyms = ( (0,6), (4,7) )
# TODO
class HuffTest(unittest.TestCase):

    def test_huff_tree(self):

        huff = huffman.HuffTree()
        book = huff.initCodeBook( (3, 3, 3, 3, 3, 2, 4, 4) )

        huff.loadCodeBook(book)
        bits = bitlab.bits( b'\xef' )
        syms = tuple( huff.iterHuffSyms( bits ) )
        
        # self.assertEqual( tuple(book), huffbook )
        # self.assertEqual( tuple(syms), huffsyms )