import zlib
import tempfile

from vstruct.types import *
from dissect.filelab import *

#https://msdn.microsoft.com/en-us/library/bb417343.aspx

_A_RDONLY       = 0x01  # file is read-only 
_A_HIDDEN       = 0x02  # file is hidden 
_A_SYSTEM       = 0x04  # file is a system file 
_A_ARCH         = 0x20  # file modified since last backup 
_A_EXEC         = 0x40  # run after extraction 
_A_NAME_IS_UTF  = 0x80  # szName[] contains UTF 

_F_PREV_CABINET       = 0x0001 # When this bit is set, the szCabinetPrev and szDiskPrev fields are present in this CFHEADER.
_F_NEXT_CABINET       = 0x0002 # When this bit is set, the szCabinetNext and szDiskNext fields are present in this CFHEADER.
_F_RESERVE_PRESENT    = 0x0004 # When this bit is set, the cbCFHeader, cbCFFolder, and cbCFData fields are present in this CFHEADER.

comp = venum()
comp.NONE     = 0x00 # no compression
comp.MSZIP    = 0x01 # ms decompress compression
comp.QUANTUM  = 0x02 # ms quantum compression
comp.LZX      = 0x03 # ms lzx compression

#BTYPE specifies how the data are compressed, as follows:
# 00 - no compression
# 01 - compressed with fixed Huffman codes
# 10 - compressed with dynamic Huffman codes
# 11 - reserved (error)

def btype(x):
    return (x >> 5) & 0x3

def bfinal(x):
    return bool( x >> 7) & 0x1

class CFHEADER(VStruct):

    def __init__(self):
        VStruct.__init__(self)
        self.signature     = vbytes(4)   # file signature
        self.reserved1     = uint32()   # reserved
        self.cbCabinet     = uint32()   # size of this cabinet file in bytes 
        self.reserved2     = uint32()   # reserved 
        self.coffFiles     = uint32()   # offset of the first CFFILE entry 
        self.reserved3     = uint32()   # reserved 
        self.versionMinor  = uint8()    # cabinet file format version, minor 
        self.versionMajor  = uint8()    # cabinet file format version, major 
        self.cFolders      = uint16()   # number of CFFOLDER entries in this cabinet
        self.cFiles        = uint16()   # number of CFFILE entries in this cabinet 
        self.flags         = uint16()   # cabinet file option indicators 
        self.setID         = uint16()   # must be the same for all cabinets in a set
        self.iCabinet      = uint16()   # number of this cabinet file in a set 
        self.cbOptFields   = VStruct()  # container struct for optional fields (flags based)
        #self.cbCFHeader    = uint16()   # (optional) size of per-cabinet reserved area
        #self.cbCFFolder    = uint8()    # (optional) size of per-folder reserved area
        #self.cbCFData      = uint8()    # (optional) size of per-datablock reserved area
        #self.abReserve     = vbytes()   # (optional) per-cabinet reserved area 
        #self.szCabinetPrev = vbytes()#v_zstr() # (optional) name of previous cabinet file 
        #self.szDiskPrev    = vbytes()#v_zstr() # (optional) name of previous disk 
        #self.szCabinetNext = vbytes()#v_zstr() # (optional) name of next cabinet file 
        #self.szDiskNext    = vbytes()#v_zstr() # (optional) name of next disk 

        self.cfDirArray    = VArray()
        self.cfFileArray   = VArray()

        self['flags'].vsOnset( self._onSetFlags )
        self['cFiles'].vsOnset( self._onSetFiles )
        self['cFolders'].vsOnset( self._onSetFolders )
        #self['cbCFHeader'].vsOnset( self._onSetCfHeader )

    def _onSetFiles(self):
        self.cfFileArray = varray( self.cFiles, CFFILE )()

    def _onSetFolders(self):
        abres = 0
        if self.flags & _F_RESERVE_PRESENT:
            abres = self.cbOptFields.cbCFFolder

        self.cfDirArray = varray( self.cFolders, CFFOLDER, abres=abres )()

    def _onSetFlags(self):
        f = self.flags

        # these *must* remain in this order...
        if f & _F_RESERVE_PRESENT:
            self.cbOptFields.cbCFHeader    = uint16()   # (optional) size of per-cabinet reserved area
            self.cbOptFields.cbCFFolder    = uint8()    # (optional) size of per-folder reserved area
            self.cbOptFields.cbCFData      = uint8()    # (optional) size of per-datablock reserved area
            self.cbOptFields.abReserve     = vbytes()   # (optional) per-cabinet reserved area 
            self.cbOptFields['cbCFHeader'].vsOnset( self._onSetCfHeader )

        if f & _F_PREV_CABINET:
            self.cbOptFields.szCabinetPrev  = zstr()
            self.cbOptFields.szDiskPrev     = zstr()

        if f & _F_NEXT_CABINET:
            self.cbOptFields.szCabinetNext  = zstr()
            self.cbOptFields.szDiskNext     = zstr()

    def _onSetCfHeader(self):
        self.cbOptFields['abReserve'].vsResize( self.cbOptFields.cbCFHeader )

class CFFOLDER(VStruct):
    def __init__(self, abres=0):
        VStruct.__init__(self)
        self.coffCabStart   = uint32()          # file offset of CFDATA blocs
        self.cCFData        = uint16()          # CFDATA block count
        self.typeCompress   = uint16(enum=comp)
        self.abReserve      = vbytes(abres)

class CFFILE(VStruct):
    def __init__(self):
        VStruct.__init__(self)
        self.cbFile             = uint32()
        self.uoffFolderStart    = uint32()
        self.iFolder            = uint16()
        self.date               = uint16()
        self.time               = uint16()
        self.attribs            = uint16()
        self.szName             = zstr()

class CFDATA(VStruct):
    def __init__(self,abres=0):
        VStruct.__init__(self)
        self.csum       = uint32()     # checksum of this CFDATA entry */
        self.cbData     = uint16()     # number of compressed bytes in this block */
        self.cbUncomp   = uint16()     # number of uncompressed bytes in this block */
        self.abReserved = vbytes(abres) # (optional) per-datablock reserved area */
        self.ab         = vbytes()      # compressed data bytes */

        self['cbData'].vsOnset( self._onSetCbData )

    def _onSetCbData(self):
        self['ab'].vsResize( self.cbData )

class CabLab(FileLab):

    def __init__(self, fd, off=0):
        FileLab.__init__(self, fd, off=off)
        self.addOnDemand('CFHEADER', self._getCabHeader )
        self.addOnDemand('filesbyname', self._loadFilesByName )

        self.decomps = {
            comp.MSZIP:self._deCompMsZip,
        }

    def _deCompMsZip(self, byts):
        if not byts.startswith(b'CK'):
            raise Exception('Invalid MsZip Block: %r' % (byts[:8],))

        deco = zlib.decompressobj(-15)
        ret = deco.decompress(byts[2:])
        return ret

    def _getCabHeader(self):
        return self.getStruct(0, CFHEADER)

    def _loadFilesByName(self):
        ret = {}
        for off,cff in self['CFHEADER'].cfFileArray:
            ret[cff.szName] = cff
        return ret

    def listCabFiles(self):
        '''
        Yield (name,info) tuples for files within the cab.

        Example:

            for filename,fileinfo in cab.listCabFiles():
                print('filename:%s' % (filename,))

        '''
        cfh = self['CFHEADER']
        for idx,cff in cfh.cfFileArray:
            fileinfo = dict(size=cff.cbFile,attrs=cff.attribs)
            fileinfo['comp'] = repr( cfh.cfDirArray[cff.iFolder]['typeCompress'] )
            yield cff.szName, fileinfo

    def openCabFile(self, name, fd=None):
        '''
        Returns a file like object for the named files bytes.

        ( optionally specify fd as the file like object to read into )
        '''
        cff = self['filesbyname'].get(name)
        if cff == None:
            raise Exception('CAB File Not Found: %s' % name)

        cfo = self['CFHEADER'].cfDirArray[cff.iFolder]
        if fd == None:
            fd = tempfile.SpooledTemporaryFile(max_size=1000000)

        cff.vsPrint()
        cfo.vsPrint()

        # iterate data blocks from our dir, beginning at our offset
        umin = cff.uoffFolderStart
        umax = cff.uoffFolderStart + cff.cbFile

        print('UMIN: %d UMAX: %d' % (umin,umax))

        #uncomp = b''
        lastb = b''

        deco = zlib.decompressobj(-zlib.MAX_WBITS)
        for uoff,cfd in self.iterCabData( cfo.coffCabStart ):
            #cfd.vsPrint()
            print(cfd)

            # do we want any of this one?
            if uoff >= umax:
                break

            #uncomp = deco.decompress( cfd.ab[2:] )
            if cfd.ab[:2] != b'CK':
                raise Exception('omg')

            print( len(cfd.ab) )

            #deco = zlib.decompressobj(-15)
            #if lastb:
                #deco.decompress( lastb )
                #deco.flush( zlib.Z_SYNC_FLUSH )

            #lastb = cfd.ab[2:]
            #todecomp = deco.unconsumed_tail + cfd.ab[2:]

            #deco = zlib.decompressobj(-zlib.MAX_WBITS)
            #if lastb:
                #deco.decompress( lastb )

            #lastb = cfd.ab[2:]

            comp = bytearray(cfd.ab[2:])
            #print( hex(comp[0]) )
            print('btype: %d bfinal: %s' % (btype(comp[0]),bfinal(comp[0])))
            #comp[0] &= 0x7f
            #comp[0] = comp[0] & 0x7f

            uncomp = deco.decompress( comp )
            #uncomp += deco.copy().flush()
    
            # sub-block is marked as "last" ( spin up a new decoder )
            #if comp[0] & 0x80:
                #deco = zlib.decompressobj(-zlib.MAX_WBITS)

            ulen = len(uncomp)
            if len(uncomp) != cfd.cbUncomp:
                raise Exception('Inflate Size Failure: %d (wanted: %d)' % (ulen,cfd.cbUncomp))

            print('tail: %d %d' % (len(deco.unconsumed_tail),len(deco.unused_data)))
            #uncomp += deco.copy().flush( zlib.Z_SYNC_FLUSH )
            #uncomp += deco.flush()
            print('ucomp len: %d %d' % (len(uncomp),cfd.cbUncomp ))
            #print('UNCOMP: %r' % (uncomp,))
            #uncomp += deco.flush( zlib.Z_SYNC_FLUSH )
            #uncomp += deco.flush()
            #print('TAIL: %r %r' % (uncomp, deco.unconsumed_tail,))

            if (uoff + cfd.cbUncomp) < umin:
                continue

            #deco = self.decomps.get( cfo.typeCompress )
            #if deco == None:
                #raise Exception('UnHandled Compression: %s' % cfo.typeCompress)

            #uncomp = deco( cfd.ab )

            #print(repr(cfd.ab))
            #print(repr(cfd.ab[:4]))
            #uncomp = zlib.decompress(cfd.ab[2:],-15)
            #uncomp = deco.decompress(cfd.ab[2:])
            #print('HI: %r' % (uncomp,))

            smin = 0
            if uoff < umin:
                smin = uoff - umin

            smax = cfd.cbUncomp
            if uoff + smax > umax:
                smax = umax - uoff

            #print( uncomp[smin:smax] )
            #fd.write( uncomp[smin:smax] )

        #uncomp += deco.flush()
        #print('UNCOMP: %r' % (uncomp,))
        #print('UNCOMP: %r' % (len(uncomp),))
        print('UNCOMP: %r' % (uncomp[umin:umax],))
        #fd.write( uncomp[umin:umax] )

        return fd

    def iterCabData(self, off):
        uoff = 0
        abres = 0

        cfh = self['CFHEADER']
        if cfh.flags & _F_RESERVE_PRESENT:
            abres = cfh.cbOptFields.cbCFData

        uoff = self.off + off
        while True:
            cfd = self.getStruct(off, CFDATA, abres=abres)

            yield (uoff,cfd)
            uoff += cfd.cbUncomp
            off += len( cfd )

    def getCabVersion(self):
        '''
        Retrieve a version tuple for the CAB file.
        '''
        hdr = self['CFHEADER']
        return ( hdr.versionMajor, hdr.versionMinor )

    def getCabSize(self):
        '''
        Retrieve the size ( in bytes ) of the CAB file.
        '''
        return self['CFHEADER'].cbCabinet

