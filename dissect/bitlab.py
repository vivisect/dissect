from dissect.compat import iterbytes

LSB = (0,1,2,3,4,5,6,7)
MSB = (7,6,5,4,3,2,1,0)

def bits(byts, order='big', cb=iterbytes):
    '''
    Yield generator for bits within bytes.
    '''
    bord = LSB
    if order == 'big':
        bord = MSB

    #foo = [ ((b >> shft) & 0x01) for b in cb(byts) for shft in bord ]
    #for b in foo:
    #    yield b
    for byte in cb(byts):
        for bit in [ (byte >> shft) & 0x1 for shft in bord ]:
            yield bit


def cast(bitgen,bitsize,bord='big'):
    '''
    Consume a "bitsize" integer from a bit generator.
    Example:
        # cast the next 5 bits as an int
        valu = cast(bits,5)
    '''
    ret = 0
    if bord == 'little':
        for i in range(bitsize):
            b = next(bitgen)
            ret |= b << i
    elif bord == 'big':
        for i in range(bitsize):
            b = next(bitgen)
            if b:
                ret |= (1 << (bitsize - 1 - i)) 
    return ret

class BitStream(object):
    def __init__(self, byts, order='big', cb=iterbytes):
        self.bitoff = 0
        self.bits = self.getBitGen(byts, order, cb)

    def getBitGen(self, byts, order='big', cb=iterbytes):
        bord = LSB
        if order == 'big':
            bord = MSB

        for byte in cb(byts):
            for bit in [ (byte >> shft) & 0x1 for shft in bord ]:
                self.bitoff += 1
                yield bit
        #foo = [ ((b >> shft) & 0x01) for b in cb(byts) for shft in bord ]
        #for self.bitoff, b in enumerate(foo):
        #    yield b

    def __iter__(self):
        return self.bits

    def getOffset(self):
        return self.bitoff

    def cast(self, bitsize, bord='big'):
        '''
        Consume a "bitsize" integer from a bit generator.

        Example:

            # cast the next 5 bits as an int
            valu = cast(bits,5)
        '''

        ret = 0
        if bord == 'little':
            for i in range(bitsize):
                b = next(self.bits)
                ret |= b << i
        elif bord == 'big':
            for i in range(bitsize):
                b = next(self.bits)
                if b:
                    ret |= (1 << (bitsize - 1 - i)) 
        return ret
