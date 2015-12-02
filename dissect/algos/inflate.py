import dissect.bitlab as bitlab
import dissect.algos.huffman as huff

COPY_LEN      = 16
REP_BIG_LEN   = 17
REP_TINY_LEN  = 18

END_BLOCK     = 256
MAX_MATCH     = 285

MAX_DIST      = 29
MAX_HIST      = 32768

class InflateError(Exception):pass

def cast(bits, num):
    return bits.cast(num, 'little')

# Inflate RFC1951 Compliant Decompressor
class Inflate(object):

    def __init__(self):
        self.fix_lits  = huff.HuffTree()
        self.fix_dists = huff.HuffTree()
        self.buff = [] # History buffer

        self._initFixedTrees()
    
    def getFixHuffBlock(self, bits):
        return self._decHuffBlock(bits, self.fix_lits, self.fix_dists)
        
    def getDynHuffBlock(self, bits):
        '''

        The Huffman codes for the two alphabets appear in the block
        immediately after the header bits and before the actual
        compressed data, first the literal/length code and then the
        distance code.  Each code is defined by a sequence of code
        lengths, as discussed in Paragraph 3.2.2, above.  For even
        greater compactness, the code length sequences themselves are
        compressed using a Huffman code.  The alphabet for code lengths
        is as follows:

                   0 - 15: Represent code lengths of 0 - 15
                       16: Copy the previous code length 3 - 6 times.
                           The next 2 bits indicate repeat length
                                 (0 = 3, ... , 3 = 6)
                              Example:  Codes 8, 16 (+2 bits 11),
                                        16 (+2 bits 10) will expand to
                                        12 code lengths of 8 (1 + 6 + 5)
                       17: Repeat a code length of 0 for 3 - 10 times.
                           (3 bits of length)
                       18: Repeat a code length of 0 for 11 - 138 times
                           (7 bits of length)
        '''

        hlit   = ( cast(bits, 5) + 257 )
        hdist  = ( cast(bits, 5) + 1 )
        hclen  = ( cast(bits, 4) + 4 )
        len_map = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5,
                   11, 4, 12, 3, 13, 2, 14, 1, 15]
        
        lens = [0]*19
        code_lens = [0] * (hlit + hdist)
        len_tree = huff.HuffTree()
        lit_tree = huff.HuffTree()
        dist_tree = None 

        for i in range(hclen):
            lens[len_map[i]] = cast(bits, 3)

        book = len_tree.initCodeBook(lens)
        len_tree.loadCodeBook(book)

        it = len_tree.iterHuffSyms(bits)
 
        i = 0
        val = -1
        vlen = 0
        while i < len(code_lens):
            if vlen > 0:
                code_lens[i] = val 
                vlen -= 1
            else:
                sym = next(it)
                if sym < COPY_LEN:
                    code_lens[i] = sym
                    val = sym
                else:
                    if sym == COPY_LEN:
                        if val == -1:
                            raise InflateError("Invalid code copy length")
                        vlen = cast(bits, 2) + 3
                    elif sym == REP_BIG_LEN:
                        val = 0
                        vlen = cast(bits, 3) + 3
                    elif sym == REP_TINY_LEN:
                        val = 0
                        vlen = cast(bits, 7) + 11
                    else:
                        raise InflateError("Invalid or corrupt block data")
                    i -= 1
            i += 1
        if vlen:
            raise InflateError('Invalid match length')

        lit_len = code_lens[:hlit]
        book = lit_tree.initCodeBook(lit_len)
        lit_tree.loadCodeBook(book)
        
        dist_len = code_lens[hlit:]

        if len(dist_len) != 1 or dist_len[0] != 0:
            if 0 == sum(x > 0 for x in dist_len) and dist_len.count(1) == 1:
                raise DecompError('Unhandled code book irregularity')
            dist_tree = huff.HuffTree()
            book = dist_tree.initCodeBook(dist_len)
            dist_tree.loadCodeBook(book)

        dec = self._decHuffBlock(bits, lit_tree, dist_tree)
        return dec

    # Get the INFLATE match length for symbols 257–285 (3-258 bytes)
    def _getMatchLen(self, s, bits):
        mlen = 0
        if s < 257 or s > 285:
            raise InflateError('Invalid match sym')
        if s <= 264:
            mlen = s - 254
        elif s <= 284:
            xbits = int((s - 261) / 4)
            mlen = (((s - 265) % 4 + 4) << xbits) + 3 + cast(bits, xbits)
        elif s == MAX_MATCH:
            mlen = 258
        else:
            raise InflateError('Invalid match length')
        return mlen

    def _getDist(self, s, bits):
        dist = 0
        
        if s > 29:
            raise InflateError('Invalid distance code')
        
        if s <= 3:
            dist = s + 1
        else:
            xbits = int((s / 2) - 1)
            dist = ((s % 2 + 2) << xbits) + 1 + cast(bits, xbits)
        return dist

    def _updateHistBuff(self):
        '''
        Roll the history buffer so it remains at its maxium size.
        '''
        self.buff = self.buff[-MAX_HIST:]

    def _initFixedTrees(self):
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

        symbits = [ 8 for i in range(144) ]
        symbits.extend( [ 9 for i in range(144, 256) ] )
        symbits.extend( [ 7 for i in range(256, 280) ] )
        symbits.extend( [ 8 for i in range(280, 288) ] )

        # Literal Length Codes
        lit_codes = self.fix_lits.initCodeBook(symbits)
        self.fix_lits.loadCodeBook(lit_codes)

        distbits = [ 5 for i in range(32) ]
        dist_codes = self.fix_dists.initCodeBook(distbits)
        self.fix_dists.loadCodeBook(dist_codes)

    def _decHuffBlock(self, bits, lit_tree, dist_tree):
        '''
        Decompress the huffman block using the supplied ltieral and distance trees.
        '''
        out = []
        if not lit_tree:
            raise InflateError('Invalid literal code tree')

        dit = dist_tree.iterHuffSyms(bits)
        for sym in lit_tree.iterHuffSyms(bits):
            # Its a literal symbol
            if sym < END_BLOCK:
                out.append(sym)
                self.buff.append(sym)
            # End of this block return back out
            elif sym == END_BLOCK:
                self._updateHistBuff()
                return out
            else:
                # It needs a lookup
                mlen = self._getMatchLen(sym, bits)
                d = next(dit)
                dist = self._getDist(d, bits)
                
                while mlen > dist:
                    out += self.buff[-dist:]
                    self.buff += self.buff[-dist:]
                    mlen -= dist
                if mlen == dist:
                    out += self.buff[-dist:]
                    self.buff += self.buff[-dist:]
                else:
                    out += self.buff[-dist:mlen-dist]
                    self.buff += self.buff[-dist:mlen-dist]
        # Should never get here
        raise InflateError('Failed to find end of block sym')
