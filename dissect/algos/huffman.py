import collections
from dissect.bitlab import cast

class OffHuffTree(Exception):pass

def bitvals(valu,bits=8):
    #HACK ugly for speed
    return [ (valu >> shft) & 0x1 for shft in range(bits-1, -1, -1) ]

class HuffTree(object):
    '''
    A huffman encoding tree.
    '''
    # The Huffman codes used for each alphabet in the "deflate"
    # format have two additional rules:

    # * All codes of a given bit length have lexicographically
    #   consecutive values, in the same order as the symbols
    #   they represent;

    # * Shorter codes lexicographically precede longer codes.

    def __init__(self):
        self.clear()

    def clear(self):
        self.root = [None,[None,None]] # root of the huffman binary tree
        self.codebysym = {}

    def iterHuffSyms(self, bits, offset=0):
        '''
        Use the HuffTree to decode bits yielding (bitoff,sym) tuples.

        Example:

            import dissect.bitlab as bitlab

            bits = bitlab.bits( byts )
            for bit,sym in huff.iterHuffSyms( bits ):
                dostuff()
        '''
        node = self.root
        for bit in bits:
            node = node[1][bit]
            if node == None:
                raise OffHuffTree()

            if node[0] != None:
                yield node[0]
                node = self.root

    def getCodeBySym(self, sym):
        '''
        Return a (bits,code) tuple by symbol.

        Example:

            bitcode = huff.getCodeBySym(x)
            if bitcode != None:
                bits,code = bitcode
                stuff()

        '''
        return self.codebysym.get(sym)

    def addHuffNode(self, sym, bits, code):
        '''
        Add a symbol to the huffman tree.

        Example:

            huff.addHuffNode( 'A', 3, 0b101 )

        '''
        node = self.root
        for bit in bitvals(code,bits):
            step = node[1][bit]
            if step == None:
                step = [ None, [None,None] ]
                node[1][bit] = step
            node = step

        if node[0]:
            raise OffHuffTree('Huffman node conflict')
        node[0] = sym
        
        if self.getCodeBySym(sym):
            raise OffHuffTree('Huffman sym conflict')
        self.codebysym[ sym ] = (bits,code)

    def loadCodeBook(self, codebook):
        '''
        Load a list of (sym,bits,code) tuples into the tree.

        Example:

            codebook = huff.initCodeBook( symbits )

            huff.loadCodeBook(codebook)

        '''
        [ self.addHuffNode(s,b,c) for (s,b,c) in codebook ]

    def initCodeBook(self, symbits):
        '''
        As per rfc1951, use a list of symbol code widths to make a codebook:

        Notes:

        Consider the alphabet ABCDEFGH, with bit lengths (3, 3, 3, 3, 3, 2, 4, 4)

            Symbol Length   Code
            ------ ------   ----
            A       3        010
            B       3        011
            C       3        100
            D       3        101
            E       3        110
            F       2         00
            G       4       1110
            H       4       1111
        '''

        nbits = collections.defaultdict(int)
        for bits in symbits:
            nbits[ bits ] += 1

        nbits[0] = 0

        code = 0
        maxbits = max( nbits.keys() )

        codebase = [0]
        for bits in range( maxbits ):
            code = ( code + nbits[ bits ] ) << 1
            codebase.append( code )

        codebook = []
        for sym in range( len( symbits ) ):
            bits = symbits[sym]
            code = codebase[bits]
            codebase[bits] += 1
            if bits:
                codebook.append( (sym,bits,code) )
        
        return codebook

