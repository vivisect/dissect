import tempfile
from io import BytesIO

from vstruct.types import *
from dissect.filelab import *
import dissect.bitlab as bitlab
import dissect.algos.mszip as mszip 
import dissect.algos.lzx as lzx

class OffCabFile(Exception):pass

#https://msdn.microsoft.com/en-us/library/bb417343.aspx

_CAB_MAGIC      = b'MSCF'
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
        self.cbFile             = uint32()   # uncompressed size of this file in bytes
        self.uoffFolderStart    = uint32()   # uncompressed offset of this file in the folder
        self.iFolder            = uint16()   # index into the CFFOLDER area
        self.date               = uint16()   # date stamp for this file
        self.time               = uint16()   # time stamp for this file
        self.attribs            = uint16()   # attribute flags for this file
        self.szName             = zstr()     # name of this file

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
            comp.NONE:self._deCompNoneBlock,
            comp.MSZIP:self._deCompMsZipBlock,
            comp.QUANTUM:self._deCompQuantumBlock,
            comp.LZX:self._deCompLzxBlock
        }


    def _deCompNoneBlock(self, itblks, comp_type=None):
        for d in itblks:
            yield d.ab

    def _deCompLzxBlock(self, itblks, comp_type):
        lzxd = lzx.Lzx(comp_type)
        for d in lzxd.decompBlock(itblks):
            yield d

    def _deCompMsZipBlock(self, itblks, comp_type=None):
        mszipd = mszip.MsZip()
        for d in mszipd.decompBlock(itblks):
            yield d

    def _deCompQuantumBlock(self, itblks, comp_type=None):
            raise NotImplementedError('Quantum is not support...yet')

    def _getCabHeader(self):
        hdr = self.getStruct(0, CFHEADER)
        if _CAB_MAGIC != hdr.signature:
            raise OffCabFile('Invalid CAB File Header: %r' % (hdr.signature,))
        return hdr

    def _loadFilesByName(self):
        ret = {}
        for off,cff in self['CFHEADER'].cfFileArray:
            ret[cff.szName] = cff
        return ret

    def getCabFiles(self):
       '''
        
        Example:

            for filename, finfo, fd in cab.getCabFiles(self):
                fdata = fd.read()
       ''' 
       cfh = self['CFHEADER']
       ifldr = None
       fdata = b''
       for fname,finfo in self.listCabFiles():
           fsize = finfo['size']
           uoff = finfo['uoff']
           if finfo['ifldr'] != ifldr:
               ifldr = finfo['ifldr']
               fldr = cfh.cfDirArray[finfo['ifldr']]
               calg = fldr.typeCompress & 3
               icd = self.iterCabData(fldr.coffCabStart, fldr.cCFData)
               dblk = self.decomps[calg](icd, fldr.typeCompress)

           while fsize > len(fdata):
               fdata += next(dblk)
           
           bio = BytesIO(fdata[:fsize])
           fdata = fdata[fsize:]
           yield (fname, finfo, bio)


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
            fileinfo['ifldr'] = cff.iFolder
            fileinfo['uoff'] = cff.uoffFolderStart
            yield cff.szName, fileinfo

    def iterCabData(self, off, cnt):
        '''
        Yield CFDATA blocks within the cab.
        '''

        uoff = 0
        abres = 0

        cfh = self['CFHEADER']
        if cfh.flags & _F_RESERVE_PRESENT:
            abres = cfh.cbOptFields.cbCFData

        cda = self.getStruct(off, varray(cnt, CFDATA, abres=abres))
        
        for idx,cd in cda:
            yield cd

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

