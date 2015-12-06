import sys
import ctypes
import dissect.algos.huffman as huffman
import dissect.bitlab as bitlab
from dissect.compat import iterbytes

LZX_FRAME_SIZE        = 32768
INSTR_CALL            = 0xE8
NUM_CHARS             = 256
BTYPE_INVALID         = 0
BTYPE_VERBATIM        = 1
BTYPE_ALIGNED         = 2
BTYPE_UNCOMPRESSED    = 3
NUM_SECONDARY_LENGTHS = 249
NUM_PRIMARY_LENGTHS   = 7
MIN_MATCH             = 2

class LzxError(Exception):pass

class LzxHuffTree(huffman.HuffTree):
    '''
    Extended Huffman Tree object with LZX specific methods
    '''
    slots = (30, 32, 34, 36, 38, 42, 50, 66, 98, 162, 290)
    
    def __init__(self):
        huffman.HuffTree.__init__(self)
        self.lens = [0] * 2000
        self.bytmode = False

    def cast(self, bits, num):
        return bits.cast(num,'big')

    def getWordBytes(self, iterblk):
        '''
        LZX runs are stored as little endian. This callback is used by the
        bitstream object to consume bytes for bit conversion
        '''
        # Need to ability to switch to a byte stream in the case of
        # uncompressed blocks
        for frm in iterblk:
            byts = frm.ab
            off = 0
            
            while off < len(byts):
                if self.bytmode:
                    yield byts[off]
                    off += 1
                else:
                    b2 = byts[off + 1]
                    b1 = byts[off]
                    yield b2
                    yield b1
                    off += 2

    def getLens(self):
        '''
        Return the LZX length array
        '''
        return self.lens

    def updateLengths(self, bits, start, stop):
        '''
        Update the LZX length arrays
        '''
        ptree = huffman.HuffTree()
        tlens = [self.cast(bits, 4) for i in range(20)]
        book = ptree.initCodeBook(tlens)
        ptree.loadCodeBook(book)

        it = ptree.iterHuffSyms(bits)
        i = start
        while i < stop:
            sym = next(it)
            if sym == 17:
               run = self.cast(bits, 4) + 4
               self.lens[i:i+run] = [0]*run 
            elif sym == 18:
               run = self.cast(bits, 5) + 20
               self.lens[i:i+run] = [0]*run 
            elif sym == 19:
               run = self.cast(bits, 1) + 4
               nsym = next(it)
               sym = self.lens[i] - nsym
               if sym < 0:
                   sym += 17
               self.lens[i:i+run] = [sym]*run
            else:
               sym = (self.lens[i] - sym)
               if sym < 0:
                   sym += 17
               self.lens[i] = sym 
               run = 1
            i += run

class Lzx(LzxHuffTree):
    '''
    LZX Decompressor
    '''
    def __init__(self, comp_type):
        self.debug = []
        self.test  = False
        LzxHuffTree.__init__(self)
        self.wbits = (comp_type >> 8) & 0x1f 
        self.wsize = 1 << self.wbits
        self.win   = memoryview(bytearray(self.wsize)) 
        self.frmcnt = 0
        self.ifs  = 0
        self.winpos = 0
        self.intelbuf = [0] * LZX_FRAME_SIZE
        self.icp = 0
        self.atree = LzxHuffTree() 
        self.mtree = LzxHuffTree()
        self.ltree = LzxHuffTree()
        self.decomps = { BTYPE_VERBATIM     : (self._initVerb, self.decVerbatim),
                         BTYPE_ALIGNED      : (self._initAlign, self.decAligned),
                         BTYPE_UNCOMPRESSED : (self._initUncomp, self.decUncomp) }

        rng = (15, 22)
        # Create the extra_bits slots
        self.xbits = [] 
        j = 0
        for i in range(51):
            self.xbits.append(j)
            self.xbits.append(j)
            if i != 0 and j < 17:
                j += 1
        
        # Create the position base slots
        self.pbase = []
        j = 0
        for i in range(51):
            self.pbase.append(j)
            j += 1 << self.xbits[i]

        if self.wbits not in range(rng[0], rng[1]):
            raise LzxError('Invalid window size')
 
        self.offs = LzxHuffTree.slots[self.wbits - 15] << 3 
        self.ival = 0
        self.r0, self.r1, self.r2 = 1,1,1
        self.run_num = 0

    def getBlockLen(self, bits):
        '''
        Get the length of an LZX block from a bitstream object
        '''
        hi = self.cast(bits, 16)
        lo = self.cast(bits, 8)
        return (hi << 8) | lo

    def _initVerb(self, bits):
        '''
        Initialize parser to process an verbatim LZX block from a bitstream object
        '''
        self.mtree.clear()
        self.ltree.clear()
        # Create the main tree
        self.mtree.updateLengths(bits, 0, NUM_CHARS)
        self.mtree.updateLengths(bits, NUM_CHARS, NUM_CHARS + self.offs)
        mlens = self.mtree.getLens() 
        book = self.mtree.initCodeBook(mlens)
        self.mtree.loadCodeBook(book)
        
        # Check for preprocessing
        self.ival = mlens[INSTR_CALL]
        
        # Get the length tree
        self.ltree.updateLengths(bits, 0, NUM_SECONDARY_LENGTHS)
        llens = self.ltree.getLens()
        book = self.ltree.initCodeBook(llens)
        self.ltree.loadCodeBook(book)

    def _initAlign(self, bits):
        self.atree.clear()
        lens = [self.cast(bits, 3) for i in range(8)]
        book = self.atree.initCodeBook(lens)
        self.atree.loadCodeBook(book)
        self._initVerb(bits)

    def _initUncomp(self, bits):
        '''
        Initialize parser to process an uncompressed LZX block from a bitstream object
        '''
        need = 16 - (bits.getOffset() % 16)
        self.cast(bits, need)
        
        self.ival = 1
        
        self.r0 = self.readInt(bits) 
        self.r1 = self.readInt(bits)
        self.r2 = self.readInt(bits) 

    def readInt(self, bits):
        '''
        Read a LZX dword from a supplied bitstream object
        '''
        byts = self.readBytes(bits, 4)
        return int.from_bytes(byts, 'little')
    
    def readBytes(self, bits, cnt):
        '''
        Read bytes from a bitstream object and byte flip. The byte flip is 
        necessary because LZX words are stored as big endian
        '''
        out = []
        i = 0

        self.bytmode = True
        for i in range(cnt):
            out.append(self.cast(bits, 8))
        self.bytmode = False

        return out

    def decAligned(self, bits, blen):
        '''
        Decompress and yield LZX align frame from a bitstream object
        '''
        run = 0
        remains = blen
        mit = self.mtree.iterHuffSyms(bits)
        lit = self.ltree.iterHuffSyms(bits)
        ait = self.atree.iterHuffSyms(bits)

        # Max bytes for this run
        maxrun = self._getFrameAlign(bits)

        for sym in mit:
            if sym < NUM_CHARS:
                self._winAppend(sym)
                run += 1
            else:
                sym -= NUM_CHARS
                # Get the match len
                mlen = sym & NUM_PRIMARY_LENGTHS
                if mlen == NUM_PRIMARY_LENGTHS:
                    mlen += next(lit) 
            
                mlen += MIN_MATCH
                # Get the match offset
                moff = sym >> 3
                if moff > 2:
                    ext  = self.xbits[moff]
                    moff = self.pbase[moff] - 2 
                    if ext > 3:
                        ext -= 3
                        vbits = self.cast(bits, ext)
                        moff += (vbits << 3)
                        moff += next(ait)
                    elif ext == 3:
                        moff += next(ait)
                    elif ext > 0:
                        vbits = self.cast(bits, ext)
                        moff += vbits
                    else:
                        moff = 1
                    self.r2 = self.r1
                    self.r1 = self.r0
                    self.r0 = moff
                elif moff == 0:
                    moff = self.r0
                elif moff == 1:
                    moff = self.r1
                    self.r1 = self.r0
                    self.r0 = moff
                else:
                    moff = self.r2
                    self.r2 = self.r0
                    self.r0 = moff
            
                if moff > self.winpos:
                    rem  = moff - self.winpos
                    mach = self.wsize - rem 
                    if rem < mlen:
                        mlen -= rem
                        rep = self._getAbsView(mach, rem)
                        self._setWinView(0, rep)
                        self.winpos += rem
                        run += rem
                        mach = 0 
                    rep = self._getAbsView(mach, mlen)
                    self._setWinView(0, rep)
                    self.winpos += mlen
                    run += mlen
                else:
                    [ self._winAppend(self.win[self.winpos-moff]) for i in range(mlen) ]
                    run += mlen

            if self.winpos % LZX_FRAME_SIZE == 0:
                self.alignWord(bits)
            if run >= remains:
                yield self._getWinView(-run, run)
                raise StopIteration

            if run >= maxrun:
                maxrun = LZX_FRAME_SIZE
                yield self._getWinView(-run, run)
                remains -= run
                run = 0
        
    def decVerbatim(self, bits, blen):
        '''
        Decompress and yield LZX verbatim frame from a bitstream object
        '''
        remains = blen
        run = 0
        lit = self.ltree.iterHuffSyms(bits)
        mit = self.mtree.iterHuffSyms(bits)
       
        # Max bytes for this run 
        maxrun = self._getFrameAlign(bits) 
        for sym in mit:
            
            if sym < NUM_CHARS:
                self._winAppend(sym)
                run += 1
            else:
                sym -= NUM_CHARS
                mlen = sym & NUM_PRIMARY_LENGTHS
                if mlen == NUM_PRIMARY_LENGTHS:
                    mlen += next(lit)
                
                mlen += MIN_MATCH
            
                # Get the match offset
                moff = sym >> 3
                if moff > 3:
                    ext  = self.xbits[moff]
                    vbits = self.cast(bits, ext)
                    moff = self.pbase[moff] - 2 + vbits
                    self.r2 = self.r1
                    self.r1 = self.r0
                    self.r0 = moff
                elif moff == 0:
                    moff = self.r0
                elif moff == 1:
                    moff = self.r1
                    self.r1 = self.r0
                    self.r0 = moff
                elif moff == 2:
                    moff = self.r2
                    self.r2 = self.r0
                    self.r0 = moff
                else:
                    moff = 1
                    self.r2 = self.r1
                    self.r1 = self.r0
                    self.r0 = moff

                if moff > self.winpos:
                    rem  = moff - self.winpos
                    mach = self.wsize - rem 
                    if rem < mlen:
                        mlen -= rem
                        rep = self._getAbsView(mach, rem)
                        self._setWinView(0, rep)
                        self.winpos += rem
                        run += rem
                        mach = 0 
                    rep = self._getAbsView(mach, mlen)
                    self._setWinView(0, rep)
                    self.winpos += mlen
                    run += mlen
                else:
                    [ self._winAppend(self.win[self.winpos-moff]) for i in range(mlen) ]
                    run += mlen
            
            if self.winpos % LZX_FRAME_SIZE == 0:
                self.alignWord(bits)
            if run >= remains:
                yield self._getWinView(-run, run)
                raise StopIteration

            if run >= maxrun:
                maxrun = LZX_FRAME_SIZE
                yield self._getWinView(-run, run)
                remains -= run
                run = 0
    
    def _winAppend(self, item):
        self.win[self.winpos] = item
        self.winpos += 1

    def _getAbsView(self, offset, nbytes):
        return self.win[offset : offset + nbytes]

    def _setAbsView(self, offset, data):
        self.win[offset : offset + len(data)] = data

    def _getWinView(self, offset, nbytes):
        return self.win[self.winpos + offset : self.winpos + offset + nbytes].tolist()

    def _setWinView(self, offset, data):
        self.win[self.winpos + offset : self.winpos + offset + len(data)] = data

    def decUncomp(self, bits, blen):
        '''
        Decodes and yields an uncompressed LZX frame
        '''
        remains = blen
        while remains:
            # Get the bytes left in this frame
            align = self._getFrameAlign(bits) 
            # Is the window currently frame aligned?
            if align == 0:
                need = LZX_FRAME_SIZE
            else:
                need = align
            
            if need > remains:
                need = remains

            byts = self.readBytes(bits, need)
            [self._winAppend(b) for b in byts]
            yield byts
            remains -= need

    def _getFrameAlign(self, bits):
        '''
        Get the number of bytes needed to make the window aligned
        on a frame boundary (32768 bytes)
        '''
        return LZX_FRAME_SIZE - (self.winpos % LZX_FRAME_SIZE)

    def alignWord(self, bits):
        '''
        Align the given bitstream object to word (16-bit) alignment
        '''
        need = (16) - bits.getOffset() % 16
        if need == 16:
            # Already word aligned, leave
            return
        bits.cast(need)

    def getIntelHeader(self, bits):
        fs = 0
        # Check for preprocessing
        if self.cast(bits, 1):
            hi = self.cast(bits, 16)
            lo = self.cast(bits, 16)
            fs = (hi << 16) | lo
        return fs
   
    def getBlockHeader(self, bits):
        '''
        Return the block type and block length from a block header
        '''
        # Get the block type
        btype = self.cast(bits, 3)
        # Get the block length
        blen  = self.getBlockLen(bits)
        return btype,blen

    def _decIntel(self, fsize):
       '''
       Decode intel preprocessing if necessary
       '''
       self.debug += self._getWinView(-fsize, fsize)
       if not self.ival or not self.ifs or self.frmcnt > LZX_FRAME_SIZE and fsize <= 10:
           if self.ifs:
               self.icp += fsize
           return self._getWinView(-fsize, fsize)

       curpos = ctypes.c_int(self.icp).value
       ibuf =  self._getWinView(-fsize, fsize)

       # Find all occurances of a 'call' byte
       indices = [i for i, b in enumerate(ibuf) if b == INSTR_CALL]
       if not len(indices):
           self.icp += fsize
           return self._getWinView(-fsize, fsize)

       # Validate the markers
       markers = [indices[0]]
       for l in indices:
            if l - markers[-1] >= 5 and l < (len(ibuf)-10):
                markers.append(l)

       for i, idx in enumerate(markers):

            if i == 0:
                curpos += idx
            else:
                curpos += (idx - markers[i-1]) 

            idx += 1

            absoff = ctypes.c_int((ibuf[idx] | (ibuf[idx+1]<<8) | 
                                  (ibuf[idx+2]<<16) | (ibuf[idx+3]<<24) ))
            absoff = absoff.value
            prev = absoff
            if absoff >= -(0xFFFFFFFF & curpos) and absoff < self.ifs:
                if absoff >= 0:
                    reloff = absoff - curpos 
                else:
                    reloff = absoff + self.ifs

                ibuf[idx]   = (0xFF & reloff)
                ibuf[idx+1] = (0xFF & (reloff >> 8))
                ibuf[idx+2] = (0xFF & (reloff >> 16))
                ibuf[idx+3] = (0xFF & (reloff >> 24))
    
       self.icp += fsize
       return ibuf

    def _postProcess(self, frame):
       
        # Check if this is the final frame
        if len(frame) >= self.rawcb:
            fsize = len(frame)
        else:
            fsize = LZX_FRAME_SIZE

        fix = self._decIntel(fsize)
        return fix

    # TODO currently expects an iterator of CFDATA objects
    def decompBlock(self, iterblk):
        '''
        Decompress and yield uncompressed byte blocks via a CFDATA iterator
        '''
        blen   = 0
        btype  = 0
        out    = []
        # Parse out the blocks
        blocks = [b for b in iterblk]
        # Get the total amount of uncompressed
        self.rawcb = sum([cf.cbUncomp for cf in blocks])

        bits = bitlab.BitStream(blocks, order='big', cb=self.getWordBytes)
        # Read Intel Header
        self.ifs = self.getIntelHeader(bits)
        while self.rawcb:
            # If the previous block was uncompressed and misaligned (16-bit) 
            # realign now
            if btype == BTYPE_UNCOMPRESSED and (blen & 1):
                self.readBytes(bits, 1)
           
            btype,blen = self.getBlockHeader(bits)
            self.decomps[btype][0](bits)
            run = blen
            for frame in self.decomps[btype][1](bits, blen):

                out += frame
                if len(out) == LZX_FRAME_SIZE or len(frame) == self.rawcb:
                    self.frmcnt += 1
                    fdata = self._postProcess(out)
                    yield bytes(fdata)
                    out = []
               
                if self.winpos >= self.wsize:
                    self.winpos = 0

                run -= len(frame)
                self.rawcb -= len(frame)
                if run == 0:
                    break


