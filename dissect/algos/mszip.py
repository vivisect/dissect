import dissect.bitlab as bitlab
import dissect.algos.inflate as inflate

#BTYPE specifies how the data are compressed, as follows:
# 00 - no compression
# 01 - compressed with fixed Huffman codes
# 10 - compressed with dynamic Huffman codes
# 11 - reserved (error)
TYPE_UNCOMP  = 0x0
TYPE_FIXED   = 0x1
TYPE_DYNAMIC = 0x2
TYPE_INVALID = 0x3

class MsZipError(Exception):pass

class MsZip(inflate.Inflate):

    def __init__(self):
        inflate.Inflate.__init__(self)

        self.decomps = {
            TYPE_UNCOMP:self._getUncompBlock,
            TYPE_FIXED:self._deCompFixedHuffman,
            TYPE_DYNAMIC:self._deCompDynHuffman,
            TYPE_INVALID:self._invalidBlock
        }

    def cast(self, bits, num):
        return bits.cast(num,'little')

    #TODO: expects a CFDATA iterator
    def decompBlock(self, iterblk):

        for frame in iterblk:
            byts = frame.ab
            if not byts.startswith(b'CK'):
                raise MsZipError('Invalid MsZip Block: %r' % (byts[:8],))

            bits = bitlab.BitStream(byts[2:], order='little')

            final = 0
            msblock = []
            while not final:
                final = self.cast(bits, 1)
                bt = self.cast(bits, 2)
                msblock.extend(self.decomps[bt](bits, byts))
            yield bytes(msblock)

    def _invalidBlock(self, bits, byts=None):
        raise MsZipError('Invalid block type')

    def _deCompDynHuffman(self, bits, byts=None):
        return self.getDynHuffBlock(bits)

    def _deCompFixedHuffman(self, bits, byts=None):
        return self.getFixHuffBlock(bits)

    def _getUncompBlock(self, bits, byts):
        # TODO Assuming we are at index 3 here
        self.cast(bits, 5)
        dlen = self.cast(bits, 16)
        clen = self.cast(bits, 16)
        out = []
        if (dlen ^ 0xFFFF) != clen:
            raise DeflateError('Invalid uncompressed block length')

        return byts[ 5 : 5 + dlen]