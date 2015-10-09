import collections

class OffHuffTree(Exception):pass

def bitvals(valu,bits=8):
    #HACK ugly for speed
    return [ (valu >> shft) & 0x1 for shft in range(bits-1, -1, -1) ]

class HuffTree:
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
        self.root = (None,[None,None]) # root of the huffman binary tree
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
        bitoff = 0

        pathbits = 0
        node = self.root
        for bit in bits:
            node = node[1][bit]
            if node == None:
                raise OffHuffTree()

            pathbits += 1

            if node[0] != None:
                yield ( bitoff, node[0] )
                node = self.root
                bitoff += pathbits
                pathbits = 0

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
        node[0] = sym

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
            codebook.append( (sym,bits,code) )

        return codebook

class HuffRfc1951Fixed(HuffTree):
    '''
    A HuffTree which is constucted pre-loaded with the rfc1951 fixed tree.

    From rfc1951:

          3.2.6. Compression with fixed Huffman codes (BTYPE=01)

         The Huffman codes for the two alphabets are fixed, and are not
         represented explicitly in the data.  The Huffman code lengths
         for the literal/length alphabet are:

                   Lit Value    Bits        Codes
                   ---------    ----        -----
                     0 - 143     8          00110000 through
                                            10111111
                   144 - 255     9          110010000 through
                                            111111111
                   256 - 279     7          0000000 through
                                            0010111
                   280 - 287     8          11000000 through
                                            11000111

    '''
    def __init__(self):
        HuffTree.__init__(self)
        symbits = [ 8 for i in range(144) ]
        symbits.extend( [ 9 for i in range( (255 - 144) + 1 ) ] )
        symbits.extend( [ 7 for i in range( (256 - 279) + 1 ) ] )
        symbits.extend( [ 8 for i in range( (280 - 287) + 1 ) ] )

        book = self.initCodeBook(symbits)

        self.loadCodeBook(book)
