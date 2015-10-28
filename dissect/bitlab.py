from dissect.compat import iterbytes

LSB = (0,1,2,3,4,5,6,7)
MSB = (7,6,5,4,3,2,1,0)

def bits(byts, reverse=False, expand=True):
    '''
    Yield generator for bits within bytes.
    '''
    bord = LSB
    if reverse:
        bord = MSB
    if expand:
        foo = [ ((b >> shft) & 0x01) for b in iterbytes(byts) for shft in bord ]
        for b in foo:
            yield b
    else:
        for byt in iterbytes(byts):
            # HACK this is super ugly in order to go faster...
            for bit in [ (byt >> shft) & 0x1 for shft in bord ]:
                yield bit

def cast(bitgen,bitsize):
    '''
    Consume a "bitsize" integer from a bit generator.
    Example:
        # cast the next 5 bits as an int
        valu = cast(bits,5)
    '''
    ret = 0
    for i in range(bitsize):
        x = next(bitgen)
        ret |= x << i
    return ret

class BitStream(object):
    def __init__(self, byts):
        bord = LSB
        if reverse:
            bord = MSB
        self.bits = [ ((b >> shft) & 0x01) for b in iterbytes(byts) for shft in bord ]
        self.idx = 0

    def __iter__(self):
        return self

    def __next__(self):
        try:
            ret = self.bits[self.idx]
            self.idx += 1
            return ret
        except IndexError:
            self.idx = 0
            raise StopIteration

    def getBitOff(self):
        return self.idx

    def alignToByte(self):
        nbits = (8) - self.idx % 8
        if nbits == 8:
            return
        self.idx += nbits

    def cast(self, bitsize):
        '''
        Consume a "bitsize" integer from a bit generator.

        Example:

            # cast the next 5 bits as an int
            valu = cast(bits,5)
        '''

        ret = 0
        for i,val in enumerate(self.bits[self.idx : self.idx + bitsize]):
            ret |= val << i
        self.idx += bitsize
        return ret
