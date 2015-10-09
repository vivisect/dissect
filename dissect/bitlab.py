from dissect.compat import iterbytes

def bits(byts):
    '''
    Yield generator for bits within bytes.
    '''
    for byt in iterbytes(byts):
        # HACK this is super ugly in order to go faster...
        for bit in [ (byt >> shft) & 0x1 for shft in (7,6,5,4,3,2,1,0) ]:
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
        ret = ( ret << 1 ) | next(bitgen)
    return ret
