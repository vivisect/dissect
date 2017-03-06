import os
import sys

from binascii import unhexlify as xeh

from vstruct2.types import *
from dissect.filelab import *

#HEAD_TYPE_MARKER        = 0x72          #marker block
#HEAD_TYPE_ARCHIVE       = 0x73          #archive header
#HEAD_TYPE_FILE_HDR      = 0x74          #file header
#HEAD_TYPE_OLD_COMMENT   = 0x75          #old style comment header
#HEAD_TYPE_OLD_AUTH      = 0x76          #old style authenticity information
#HEAD_TYPE_OLD_SUBBLOCK  = 0x77          #old style subblock
#HEAD_TYPE_OLD_RECOVERY  = 0x78          #old style recovery record
#HEAD_TYPE_OLD_AUTH2     = 0x79          #old style authenticity information
#HEAD_TYPE_SUBBLOCK      = 0x7a          #subblock

SFX_MODMAX  = 1024000 # one meg
RAR4_SIGNATURE = xeh(b'526172211a0700')
RAR5_SIGNATURE = xeh(b'526172211a070100')

def getRarOffset(fd):
    head = fd.read(SFX_MODMAX * 2)
    offset = head.find(RAR5_SIGNATURE)
    if offset != -1:
        return ( (5,0,0), offset + 8 )

    offset = head.find(RAR4_SIGNATURE)
    if offset != -1:
        return ( (4,0,0), offset + 7 )

    return None

# Header Types
htypes = venum()
htypes.MARK_HEAD       = 0x72
htypes.MAIN_HEAD       = 0x73
htypes.FILE_HEAD       = 0x74
htypes.COMM_HEAD       = 0x75
htypes.AV_HEAD         = 0x76
htypes.SUB_HEAD        = 0x77
htypes.PROTECT_HEAD    = 0x78
htypes.SIGN_HEAD       = 0x79
htypes.NEWSUB_HEAD     = 0x7a
htypes.ENDARC_HEAD     = 0x7b

# Main Header Flags
MHD_VOLUME          = 0x0001
MHD_COMMENT         = 0x0002
MHD_LOCK            = 0x0004
MHD_SOLID           = 0x0008
MHD_PACK_COMMENT    = 0x0010
MHD_AV              = 0x0020
MHD_PROTECT         = 0x0040
MHD_PASSWORD        = 0x0080    # The archive is password encrypted
MHD_FIRSTVOLUME     = 0x0100
MHD_ENCRYPTVER      = 0x0200

LHD_SPLIT_BEFORE   = 0x0001
LHD_SPLIT_AFTER    = 0x0002
LHD_PASSWORD       = 0x0004
LHD_COMMENT        = 0x0008
LHD_SOLID          = 0x0010
LHD_WINDOWMASK     = 0x00e0
LHD_WINDOW64       = 0x0000
LHD_WINDOW128      = 0x0020
LHD_WINDOW256      = 0x0040
LHD_WINDOW512      = 0x0060
LHD_WINDOW1024     = 0x0080
LHD_WINDOW2048     = 0x00a0
LHD_WINDOW4096     = 0x00c0
LHD_DIRECTORY      = 0x00e0
LHD_LARGE          = 0x0100
LHD_UNICODE        = 0x0200
LHD_SALT           = 0x0400
LHD_VERSION        = 0x0800
LHD_EXTTIME        = 0x1000
LHD_EXTFLAGS       = 0x2000

SKIP_IF_UNKNOWN    = 0x4000
LONG_BLOCK         = 0x8000

SIZE_SALT30        = 8
SIZE_SALT50        = 16
SIZE_IV            = 16

CRYPT_NONE         = 0
CRYPT_RAR13        = 1
CRYPT_RAR15        = 2
CRYPT_RAR20        = 3
CRYPT_RAR30        = 4
CRYPT_RAR50        = 5

CRYPT_BLOCKSIZE    = 16

class RarChunkUnkn(VStruct):
    def __init__(self):
        VStruct.__init__(self)
        self.CHUNK_BYTES = vbytes()

class MainHeader(VStruct):
    def __init__(self):
        VStruct.__init__(self)
        self.HighPosAV  = uint16()
        self.PosAV      = uint32()
        self.EncryptVer = uint8()

class Rar4Data(VStruct):

    def __init__(self):
        VStruct.__init__(self)

    def setHeadFlags(self, flags):
        pass

class MainData(Rar4Data):
    def __init__(self):
        Rar4Data.__init__(self)
        self.HighPosAv    = uint16()
        self.PosAV        = uint32()

    def setHeadFlags(self, flags):
        if flags & MHD_ENCRYPTVER:
            self.EncryptVer = uint8()

class FileData(Rar4Data):
    def __init__(self):
        Rar4Data.__init__(self)
        self.PackSize     = uint32()
        self.UnpSize      = uint32()
        self.HostOs       = uint8()
        self.FileCrc      = uint32()
        self.FileTime     = uint32()
        self.UnpVer       = uint8()
        self.Method       = uint8()
        self.NameSize     = uint16()
        self.FileAttr     = uint32()
        self.FlagFields   = VStruct()
        self.FileName     = vstr()

        def setFileNameSize():
            self['FileName'].vsResize(self.NameSize)

        self['NameSize'].vsOnset( setFileNameSize )

    def setHeadFlags(self, flags):
        # FIXME vsClear() ?
        if flags & LHD_LARGE:
            self.FlagFields.HighPackSize = uint32()
            self.FlagFields.HighUnpSize  = uint32()

        if flags & LHD_SALT:
            self.FlagFields.Salt     = vbytes(size=8)

        if flags & LHD_EXTTIME:
            raise Exception("FIXME supprort LHD_EXTTIME")

datatypes = {
    htypes.MAIN_HEAD:MainData,
    htypes.FILE_HEAD:FileData,
}
class Rar4Block(VStruct):

    def __init__(self):
        VStruct.__init__(self)

        self.HEAD_CRC       = uint16()
        self.HEAD_TYPE      = uint8(enum=htypes)
        self.HEAD_FLAGS     = uint16()
        self.HEAD_SIZE      = uint16()
        self.HEAD_DATA      = VStruct()

        self['HEAD_TYPE'].vsOnset( self._setHeadType )
        self['HEAD_FLAGS'].vsOnset( self._setHeadFlags )

    def _setHeadType(self):
        cls = datatypes.get( self.HEAD_TYPE, Rar4Data )
        self['HEAD_DATA'] = cls()

    def _setHeadFlags(self):
        self['HEAD_DATA'].setHeadFlags( self.HEAD_FLAGS )

#class MAIN_HEADER(Rar4Block):
    #def __init__(self):
        #Rar4Block.__init__(self)
        #self.HEAD_DATA.HighPosAv    = uint16()
        #self.HEAD_DATA.PosAV        = uint32()

        #if self.HEAD_FLAGS & MHD_ENCRYPTVER:
            #self.HEAD_DATA.EncryptVer   = uint8()



    #def pcb_HEAD_DATA(self):
        #remain = len(self) % 16
        #if remain:
            #self.HEAD_PAD.pad = v_bytes(size=16-remain)

    #def pcb_HEAD_SIZE(self):

        #if self.HEAD_TYPE == MAIN_HEAD:
            #self.HEAD_DATA.HighPosAv    = v_uint16()
            #self.HEAD_DATA.PosAV        = v_uint32()
            #if self.HEAD_FLAGS & MHD_ENCRYPTVER:
                #self.HEAD_DATA.EncryptVer   = v_uint8()
            #return

        #if self.HEAD_TYPE == FILE_HEAD:
            #self.HEAD_DATA.PackSize     = v_uint32()
            #self.HEAD_DATA.UnpSize      = v_uint32()
            #self.HEAD_DATA.HostOs       = v_uint8()
            #self.HEAD_DATA.FileCrc      = v_uint32()
            #self.HEAD_DATA.FileTime     = v_uint32()
            #self.HEAD_DATA.UnpVer       = v_uint8()
            #self.HEAD_DATA.Method       = v_uint8()
            #self.HEAD_DATA.NameSize     = v_uint16()
            #self.HEAD_DATA.FileAttr     = v_uint32()

            #if self.HEAD_FLAGS & LHD_LARGE:
                #self.HEAD_DATA.HighPackSize = v_uint32()
                #self.HEAD_DATA.HighUnpSize  = v_uint32()

            #filename = v_str()
            #self.HEAD_DATA.FileName     = filename

            #if self.HEAD_FLAGS & LHD_SALT:
                #self.HEAD_DATA.Salt     = v_bytes(size=8)

            #if self.HEAD_FLAGS & LHD_EXTTIME:
                #raise Exception("FIXME supprort LHD_EXTTIME")

            #def setFileNameSize(x):
                #print 'NAME SIZE',self.HEAD_DATA.NameSize 
                #filename.vsSetLength( self.HEAD_DATA.NameSize )

            #self.HEAD_DATA.vsAddParseCallback('NameSize',setFileNameSize)
            #return

            #self.HEAD_DATA.NameSize     = v_uint32()
            #self.HEAD_DATA.NameSize     = v_uint32()

            #if not self.HEAD_FLAGS & MHD_ENCRYPTVER:
                #self.BLOCK_DATA.EncryptVer = vstruct.VStruct()

    #def pcb_HEAD_FLAGS(self):
        ## a proto callback for the header
        #if self.HEAD_FLAGS & LONG_BLOCK:
            #self.ADD_SIZE = v_uint32()
        #else:
            #self.ADD_SIZE = vstruct.VStruct()

        #if self.HEAD_TYPE == MAIN_HEAD and self.HEAD_FLAGS & MHD_PASSWORD:
                #self.BLOCK_DATA.Salt = v_bytes(size=8)

    #def pcb_ADD_SIZE(self):

        # first things first, needs salt?
        #if self.HEAD_FLAGS & MHD_PASSWORD:
            #self.BLOCK_DATA.Salt = v_bytes(size=8)

        #hsize = 7
        #totsize = self.HEAD_SIZE
#
        #if not isinstance(self.ADD_SIZE, vstruct.VStruct):
            #hsize += 4
            #totsize += self.ADD_SIZE

        # We will *now* use TYPE to find out our chunk guts
        #if not self._known_block:
            #self.BLOCK_DATA = v_bytes(totsize - hsize)

import hashlib
rounds = 0x40000
roundsdiv = rounds / 16
#iblist = [ struct.pack('<I',i)[:3] for i in xrange(rounds) ]

def initIvKey30(passwd,salt):
    aesiv = [None] * 16
    aeskey = [None] * 16

    passb = passwd.encode('utf-16le')
    initkey = passb + salt
    print('PASS','->%s<-' % passwd)
    print('SALT',salt.encode('hex'))
    print('INIT',initkey.encode('hex'))

    sha1hash = hashlib.sha1()
    #sha1hash = rarsha()
    # crazy russian awesomeness/paranoia
    for i in xrange(rounds): # srsly?!?! fscking russians ;)
        sha1hash.update(initkey)
        #print "INITKEY",initkey.encode("hex")
        ib = struct.pack('<I',i)
        sha1hash.update( ib[:3] )
        #sha1hash.update( iblist[i] )

        #print "pswnum",ib[:3].encode('hex')
        if i % roundsdiv == 0:
            digest = sha1hash.digest()
            #digest = sha1hash.done()
            #print 'shaiv',digest.encode('hex')
            aesiv[ i / roundsdiv ] = digest[-1]
            #print 'AESINIT',i/roundsdiv,digest[-1].encode('hex')
            #raise 'WOOT'

    print('IV',(''.join(aesiv)).encode('hex'))
    endswap = struct.unpack_from('<4I', sha1hash.digest())
    aeskey  = struct.pack('>4I', *endswap)
    print('KEY',aeskey.encode('hex'))
    #digest = sha1hash.digest()
    #print 'PREKEY',digest.encode('hex')
    #for i in xrange(4):
        #for j in xrange(4):
            #aeskey[ (i*4) + j ] = chr( (digest[i] >> (j*8)) & 0xff )

    return ''.join(aesiv),aeskey

def aesInit(iv,key):
    from Crypto.Cipher import AES
    return AES.new(key, AES.MODE_CBC, iv)

class MissingRarSig(Exception):pass
class PasswordRequired(Exception):pass

class RarLab(FileLab):

    def __init__(self, fd):
        FileLab.__init__(self, fd)
        self.add('veroff', self._getVerOff )
        self.add('header', self._getRarHeader )

        #self.fd = None
        #self.aes = None
        self.salt = None
        #self.offset = None
        #self.trybuf = None
        #self.clearbuf = ''
        #self.version = None
        #self.mainhead = None

        #if fd != None:
            #self.parseRarHeader(fd)

    def _getVerOff(self):
        self.fd.seek(0)
        return getRarOffset(self.fd)

    def _getRarHeader(self):
        veroff = self['veroff']
        if veroff == None:
            raise MissingRarSig()

        ver,off = veroff
        block = self.getStruct(off, Rar4Block)
        if block.HEAD_TYPE != htypes.MAIN_HEAD:
            raise Exception('Invalid First Block: %d' % (block.HEAD_TYPE,))

        if block.HEAD_FLAGS & MHD_PASSWORD:
            self.salt = self.fd.read(8)

        self.blocksoff = self.fd.tell()
        return block

    def tryFilePasswd(self, passwd):
        '''
        Check the passwd agains the next encrypted header
        ( which should be of type FILE_HEAD )
        '''
        if self.trybuf == None:
            curloc = self.fd.tell()
            self.trybuf = self.fd.read(16)
            self.fd.seek(curloc)
        
        iv,key = initIvKey30(passwd,self.salt)
        aes = aesInit(iv,key)
        clearbuf = aes.decrypt(self.trybuf)
        #print 'CLEAR',clearbuf.encode('hex')
        crc,ctype,cflags,csize = struct.unpack_from('<HBHH', clearbuf)
        #print 'CTYPE',hex(ctype),hex(FILE_HEAD)
        return ctype == FILE_HEAD

    #def setFilePasswd(self, passwd):
        #'''
        #Used to set the file-wide password for decryption.
        #'''
        #iv,key = initIvKey30(passwd,self.salt)
        #self.aes = aesInit(iv,key)

    def iterRar4Files(self):

        #if self.salt != None and self.aes == None:
            #raise PasswordRequired()
        veroff = self['veroff']
        header = self['header']

        #off = veroff[1] + len(header)
        #off = veroff[1] + len(header)
        off = self.blocksoff
        while True:

            block = self.getStruct(off, Rar4Block)
            if block == None:
                break

            #block.vsPrint()

            # fail gracefully on invalid header size
            if block.HEAD_SIZE == 0:
                break

            off += block.HEAD_SIZE

            if block.HEAD_TYPE == htypes.FILE_HEAD:
                yield block

            #hdr = self.read(7)
            #crc,ctype,cflags,csize = struct.unpack('<HBHH', hdr)
            #body = self.read(csize - 7)

            #rar4 = Rar4Block()
            #rar4.vsParse( hdr )

            #if self.salt != None:
                #remain = csize % 16
                #if remain:
                    #pad = self.read( 16 - remain )
                    #print 'PAD',pad.encode('hex')

            #cls = rar4blocks.get(rar4.HEAD_TYPE)
            #if cls != None:
                #rar4 = cls()
                #rar4.vsParse(hdr+body)

            #print(rar4.tree())
            #import sys; sys.stdin.readline()

            #if ctype == MAIN_HEAD and cflags & MHD_PASSWORD:
                #if passwd == None:
                    #raise PasswordRequired()

                #salt30 = fd.read(SIZE_SALT30)
                #iv,key = initIvKey(passwd,salt)
                #self.aes = aesInit(iv,key)
                #break

            if block.HEAD_TYPE == htypes.ENDARC_HEAD:
                break

        #self.HEAD_CRC       = v_uint16()
        #self.HEAD_TYPE      = v_uint8()
        #self.HEAD_FLAGS     = v_uint16()
        #self.HEAD_SIZE      = v_uint16()

def main():

    offset = 0
    fd = file(sys.argv[1], 'rb')
    testpass = sys.argv[2]

    rar = Rar()
    rar.parseRarHeader(fd)
    rar.mainhead.tree()

    #print "FAIL TEST",rar.tryFilePasswd('asdf')
    #print "PASS TEST",rar.tryFilePasswd(testpass)

    rar.setFilePasswd(testpass)
    #print rar.read(4096).encode('hex')
    rar.iterRar4Files()
    #for x in rar.iterRar4Chunks():
        #print x
    return

    buf = fd.read(1024000)

    offset = 0

    rar4 = Rar4Block()
    offset = rar4.vsParse(buf,offset=offset)
    print(rar4.tree())

    #print 'PRE',buf[offset:offset+32].encode('hex')
    salt = buf[offset:offset+SIZE_SALT30]
    print('SALT',salt.encode('hex'))
    offset += SIZE_SALT30

    iv,key = initIvKey30(testpass,salt)
    #print 'IV',iv.encode('hex')
    #print 'KEY',key.encode('hex')
    aes = aesInit(iv,key)
    #raise 'woot'
    #print aes.decrypt(buf[offset:offset+64]).encode('hex')
    x = aes.decrypt(buf[offset:offset+64])

    rar4 = Rar4Block()
    rar4.vsParse(x)
    #offset = rar4.vsParse(buf,offset=offset)
    print(rar4.tree())

    #while offset < len(b):
        #r = RarBlock()
        #newoff = r.vsParse(b, offset=offset)
        #print 'CRC',r.HEAD_CRC,r.HEAD_TYPE
        #print r.tree(va=offset)

        #offset = newoff
        

if __name__ == '__main__':
    sys.exit(main())

