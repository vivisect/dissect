'''
The dissect module for parsing PE files.
'''
from vstruct2.types import *
from dissect.bexlab import *

DOS_MAGIC = 0x5a4d

IMAGE_DLLCHARACTERISTICS_RESERVED_1      = 1
IMAGE_DLLCHARACTERISTICS_RESERVED_2      = 2
IMAGE_DLLCHARACTERISTICS_RESERVED_4      = 4
IMAGE_DLLCHARACTERISTICS_RESERVED_8      = 8
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE    = 0x0040 # The DLL can be relocated at load time.
IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x0080 # Code integrity checks are forced. If you set this flag and a section contains only uninitialized data, set the PointerToRawData member of IMAGE_SECTION_HEADER for that section to zero; otherwise, the image will fail to load because the digital signature cannot be verified.
IMAGE_DLLCHARACTERISTICS_NX_COMPAT       = 0x0100 # The image is compatible with data execution prevention (DEP).
IMAGE_DLLCHARACTERISTICS_NO_ISOLATION    = 0x0200 # The image is isolation aware, but should not be isolated.
IMAGE_DLLCHARACTERISTICS_NO_SEH          = 0x0400 # The image does not use structured exception handling (SEH). No handlers can be called in this image.
IMAGE_DLLCHARACTERISTICS_NO_BIND         = 0x0800 # Do not bind the image.
IMAGE_DLLCHARACTERISTICS_RESERVED_1000   = 0x1000 # Reserved
IMAGE_DLLCHARACTERISTICS_WDM_DRIVER      = 0x2000 # A WDM driver.
IMAGE_DLLCHARACTERISTICS_RESERVED_4000   = 0x4000 # Reserved
IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE  = 0x8000

IMAGE_SUBSYSTEM_UNKNOWN             = 0 #Unknown subsystem.
IMAGE_SUBSYSTEM_NATIVE              = 1 #No subsystem required (device drivers and native system processes).
IMAGE_SUBSYSTEM_WINDOWS_GUI         = 2 #Windows graphical user interface (GUI) subsystem.
IMAGE_SUBSYSTEM_WINDOWS_CUI         = 3 #Windows character-mode user interface (CUI) subsystem.
IMAGE_SUBSYSTEM_OS2_CUI             = 5 #OS/2 CUI subsystem.
IMAGE_SUBSYSTEM_POSIX_CUI           = 7 #POSIX CUI subsystem.
IMAGE_SUBSYSTEM_WINDOWS_CE_GUI      = 9 #Windows CE system.
IMAGE_SUBSYSTEM_EFI_APPLICATION     = 10 #Extensible Firmware Interface (EFI) application.
IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER     = 11 #EFI driver with boot services.
IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER  = 12 #EFI driver with run-time services.
IMAGE_SUBSYSTEM_EFI_ROM             = 13 #EFI ROM image.
IMAGE_SUBSYSTEM_XBOX                = 14 #Xbox system.
IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION    = 16 #Boot application.

IMAGE_FILE_MACHINE_I386  = 0x014c
IMAGE_FILE_MACHINE_IA64  = 0x0200
IMAGE_FILE_MACHINE_AMD64 = 0x8664

machine_names = {
    IMAGE_FILE_MACHINE_I386: 'i386',
    IMAGE_FILE_MACHINE_IA64: 'ia64',
    IMAGE_FILE_MACHINE_AMD64: 'amd64',
}

machine_ptr_sizes = {
    IMAGE_FILE_MACHINE_I386: 4,
    IMAGE_FILE_MACHINE_IA64: 8,
    IMAGE_FILE_MACHINE_AMD64: 8,
}

IMAGE_REL_BASED_ABSOLUTE              = 0
IMAGE_REL_BASED_HIGH                  = 1
IMAGE_REL_BASED_LOW                   = 2
IMAGE_REL_BASED_HIGHLOW               = 3
IMAGE_REL_BASED_HIGHADJ               = 4
IMAGE_REL_BASED_MIPS_JMPADDR          = 5
IMAGE_REL_BASED_IA64_IMM64            = 9
IMAGE_REL_BASED_DIR64                 = 10

IMAGE_DIRECTORY_ENTRY_EXPORT          =0   # Export Directory
IMAGE_DIRECTORY_ENTRY_IMPORT          =1   # Import Directory
IMAGE_DIRECTORY_ENTRY_RESOURCE        =2   # Resource Directory
IMAGE_DIRECTORY_ENTRY_EXCEPTION       =3   # Exception Directory
IMAGE_DIRECTORY_ENTRY_SECURITY        =4   # Security Directory
IMAGE_DIRECTORY_ENTRY_BASERELOC       =5   # Base Relocation Table
IMAGE_DIRECTORY_ENTRY_DEBUG           =6   # Debug Directory
IMAGE_DIRECTORY_ENTRY_COPYRIGHT       =7   # (X86 usage)
IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    =7   # Architecture Specific Data
IMAGE_DIRECTORY_ENTRY_GLOBALPTR       =8   # RVA of GP
IMAGE_DIRECTORY_ENTRY_TLS             =9   # TLS Directory
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    =10   # Load Configuration Directory
IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   =11   # Bound Import Directory in headers
IMAGE_DIRECTORY_ENTRY_IAT            =12   # Import Address Table
IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   =13   # Delay Load Import Descriptors
IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR =14   # COM Runtime descriptor

IMAGE_DEBUG_TYPE_UNKNOWN          =0
IMAGE_DEBUG_TYPE_COFF             =1
IMAGE_DEBUG_TYPE_CODEVIEW         =2
IMAGE_DEBUG_TYPE_FPO              =3
IMAGE_DEBUG_TYPE_MISC             =4
IMAGE_DEBUG_TYPE_EXCEPTION        =5
IMAGE_DEBUG_TYPE_FIXUP            =6
IMAGE_DEBUG_TYPE_OMAP_TO_SRC      =7
IMAGE_DEBUG_TYPE_OMAP_FROM_SRC    =8
IMAGE_DEBUG_TYPE_BORLAND          =9
IMAGE_DEBUG_TYPE_RESERVED10       =10
IMAGE_DEBUG_TYPE_CLSID            =11

IMAGE_SCN_CNT_CODE                  = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA      = 0x00000040
IMAGE_SCN_CNT_UNINITIALIZED_DATA    = 0x00000080
IMAGE_SCN_LNK_OTHER                 = 0x00000100
IMAGE_SCN_LNK_INFO                  = 0x00000200
IMAGE_SCN_LNK_REMOVE                = 0x00000800
IMAGE_SCN_LNK_COMDAT                = 0x00001000
IMAGE_SCN_MEM_FARDATA               = 0x00008000
IMAGE_SCN_MEM_PURGEABLE             = 0x00020000
IMAGE_SCN_MEM_16BIT                 = 0x00020000
IMAGE_SCN_MEM_LOCKED                = 0x00040000
IMAGE_SCN_MEM_PRELOAD               = 0x00080000
IMAGE_SCN_ALIGN_1BYTES              = 0x00100000
IMAGE_SCN_ALIGN_2BYTES              = 0x00200000
IMAGE_SCN_ALIGN_4BYTES              = 0x00300000
IMAGE_SCN_ALIGN_8BYTES              = 0x00400000
IMAGE_SCN_ALIGN_16BYTES             = 0x00500000
IMAGE_SCN_ALIGN_32BYTES             = 0x00600000
IMAGE_SCN_ALIGN_64BYTES             = 0x00700000
IMAGE_SCN_ALIGN_128BYTES            = 0x00800000
IMAGE_SCN_ALIGN_256BYTES            = 0x00900000
IMAGE_SCN_ALIGN_512BYTES            = 0x00A00000
IMAGE_SCN_ALIGN_1024BYTES           = 0x00B00000
IMAGE_SCN_ALIGN_2048BYTES           = 0x00C00000
IMAGE_SCN_ALIGN_4096BYTES           = 0x00D00000
IMAGE_SCN_ALIGN_8192BYTES           = 0x00E00000
IMAGE_SCN_ALIGN_MASK                = 0x00F00000
IMAGE_SCN_LNK_NRELOC_OVFL           = 0x01000000
IMAGE_SCN_MEM_DISCARDABLE           = 0x02000000
IMAGE_SCN_MEM_NOT_CACHED            = 0x04000000
IMAGE_SCN_MEM_NOT_PAGED             = 0x08000000
IMAGE_SCN_MEM_SHARED                = 0x10000000
IMAGE_SCN_MEM_EXECUTE               = 0x20000000
IMAGE_SCN_MEM_READ                  = 0x40000000
IMAGE_SCN_MEM_WRITE                 = 0x80000000

# Flags for the UNWIND_INFO flags field from
# RUNTIME_FUNCTION defs
UNW_FLAG_NHANDLER   = 0x0
UNW_FLAG_EHANDLER   = 0x1
UNW_FLAG_UHANDLER   = 0x2
UNW_FLAG_CHAININFO  = 0x4

# Resource Types
RT_CURSOR           = 1
RT_BITMAP           = 2
RT_ICON             = 3
RT_MENU             = 4
RT_DIALOG           = 5
RT_STRING           = 6
RT_FONTDIR          = 7
RT_FONT             = 8
RT_ACCELERATOR      = 9
RT_RCDATA           = 10
RT_MESSAGETABLE     = 11
RT_GROUP_CURSOR     = 12
RT_GROUP_ICON       = 14
RT_VERSION          = 16
RT_DLGINCLUDE       = 17
RT_PLUGPLAY         = 19
RT_VXD              = 20
RT_ANICURSOR        = 21
RT_ANIICON          = 22
RT_HTML             = 23
RT_MANIFEST         = 24

class IMAGE_BASE_RELOCATION(VStruct):
    def __init__(self):
        VStruct.__init__(self)
        self.VirtualAddress = uint32()
        self.SizeOfBlock    = uint32()

class IMAGE_DATA_DIRECTORY(VStruct):
    def __init__(self):
        VStruct.__init__(self)
        self.VirtualAddress = uint32()
        self.Size           = uint32()

class IMAGE_DOS_HEADER(VStruct):
    def __init__(self):
        VStruct.__init__(self)
        self.e_magic    = uint16()
        self.e_cblp     = uint16()
        self.e_cp       = uint16()
        self.e_crlc     = uint16()
        self.e_cparhdr  = uint16()
        self.e_minalloc = uint16()
        self.e_maxalloc = uint16()
        self.e_ss       = uint16()
        self.e_sp       = uint16()
        self.e_csum     = uint16()
        self.e_ip       = uint16()
        self.e_cs       = uint16()
        self.e_lfarlc   = uint16()
        self.e_ovno     = uint16()
        self.e_res      = VArray([uint16() for i in range(4)])
        self.e_oemid    = uint16()
        self.e_oeminfo  = uint16()
        self.e_res2     = VArray([uint16() for i in range(10)])
        self.e_lfanew   = uint32()

class IMAGE_EXPORT_DIRECTORY(VStruct):
    def __init__(self):
        VStruct.__init__(self)
        self.Characteristics    = uint32()
        self.TimeDateStamp      = uint32()
        self.MajorVersion       = uint16()
        self.MinorVersion       = uint16()
        self.Name               = uint32()
        self.Base               = uint32()
        self.NumberOfFunctions  = uint32()
        self.NumberOfNames      = uint32()
        self.AddressOfFunctions = uint32()
        self.AddressOfNames     = uint32()
        self.AddressOfOrdinals  = uint32()

class IMAGE_DEBUG_DIRECTORY(VStruct):
    def __init__(self):
      VStruct.__init__(self)
      self.Characteristics = uint32()
      self.TimeDateStamp   = uint32()
      self.MajorVersion    = uint16()
      self.MinorVersion    = uint16()
      self.Type            = uint32()
      self.SizeOfData      = uint32()
      self.AddressOfRawData= uint32()
      self.PointerToRawData= uint32()

class CV_INFO_PDB70(VStruct):
    def __init__(self):
        VStruct.__init__(self)
        self.CvSignature    = uint32()
        self.Signature      = GUID()
        self.Age            = uint32()
        self.PdbFileName    = cstr(260)

    def vsParse(self, bytez, offset=0):
        bsize = len(bytez) - offset
        self.vsGetField('PdbFileName').vsSetLength( bsize - 24 )
        return VStruct.vsParse(self, bytez, offset=offset)

class IMAGE_FILE_HEADER(VStruct):
    def __init__(self):
        VStruct.__init__(self)
        self.Machine              = uint16()
        self.NumberOfSections     = uint16()
        self.TimeDateStamp        = uint32()
        self.PointerToSymbolTable = uint32()
        self.NumberOfSymbols      = uint32()
        self.SizeOfOptionalHeader = uint16()
        self.Characteristics      = uint16()

class IMAGE_IMPORT_DIRECTORY(VStruct):
    def __init__(self):
        VStruct.__init__(self)
        self.OriginalFirstThunk = uint32()
        self.TimeDateStamp      = uint32()
        self.ForwarderChain     = uint32()
        self.Name               = uint32()
        self.FirstThunk         = uint32()

class IMAGE_IMPORT_BY_NAME(VStruct):
    def __init__(self, namelen=128):
        VStruct.__init__(self)
        self.Hint   = uint16()
        self.Name   = cstr(size=namelen)

class IMAGE_LOAD_CONFIG_DIRECTORY(VStruct):
    def __init__(self):
        VStruct.__init__(self)
        self.Size                          = uint32()
        self.TimeDateStamp                 = uint32()
        self.MajorVersion                  = uint16()
        self.MinorVersion                  = uint16()
        self.GlobalFlagsClear              = uint32()
        self.GlobalFlagsSet                = uint32()
        self.CriticalSectionDefaultTimeout = uint32()
        self.DeCommitFreeBlockThreshold    = uint32()
        self.DeCommitTotalFreeThreshold    = uint32()
        self.LockPrefixTable               = uint32()
        self.MaximumAllocationSize         = uint32()
        self.VirtualMemoryThreshold        = uint32()
        self.ProcessHeapFlags              = uint32()
        self.ProcessAffinityMask           = uint32()
        self.CSDVersion                    = uint16()
        self.Reserved1                     = uint16()
        self.EditList                      = uint32()
        self.SecurityCookie                = uint32()
        self.SEHandlerTable                = uint32()
        self.SEHandlerCount                = uint32()

class IMAGE_NT_HEADERS(VStruct):
    def __init__(self):
        VStruct.__init__(self)
        self.Signature      = vbytes(size=4)
        self.FileHeader     = IMAGE_FILE_HEADER()
        self.OptionalHeader = IMAGE_OPTIONAL_HEADER()

class IMAGE_NT_HEADERS64(VStruct):
    def __init__(self):
        VStruct.__init__(self)
        self.Signature      = vbytes(size=4)
        self.FileHeader     = IMAGE_FILE_HEADER()
        self.OptionalHeader = IMAGE_OPTIONAL_HEADER64()

class IMAGE_OPTIONAL_HEADER(VStruct):
    def __init__(self):
        VStruct.__init__(self)
        self.Magic                       = vbytes(size=2)
        self.MajorLinkerVersion          = uint8()
        self.MinorLinkerVersion          = uint8()
        self.SizeOfCode                  = uint32()
        self.SizeOfInitializedData       = uint32()
        self.SizeOfUninitializedData     = uint32()
        self.AddressOfEntryPoint         = uint32()
        self.BaseOfCode                  = uint32()
        self.BaseOfData                  = uint32()
        self.ImageBase                   = uint32()
        self.SectionAlignment            = uint32()
        self.FileAlignment               = uint32()
        self.MajorOperatingSystemVersion = uint16()
        self.MinorOperatingSystemVersion = uint16()
        self.MajorImageVersion           = uint16()
        self.MinorImageVersion           = uint16()
        self.MajorSubsystemVersion       = uint16()
        self.MinorSubsystemVersion       = uint16()
        self.Win32VersionValue           = uint32()
        self.SizeOfImage                 = uint32()
        self.SizeOfHeaders               = uint32()
        self.CheckSum                    = uint32()
        self.Subsystem                   = uint16()
        self.DllCharacteristics          = uint16()
        self.SizeOfStackReserve          = uint32()
        self.SizeOfStackCommit           = uint32()
        self.SizeOfHeapReserve           = uint32()
        self.SizeOfHeapCommit            = uint32()
        self.LoaderFlags                 = uint32()
        self.NumberOfRvaAndSizes         = uint32()
        self.DataDirectory               = VArray([IMAGE_DATA_DIRECTORY() for i in range(16)])

class IMAGE_OPTIONAL_HEADER64(VStruct):
    def __init__(self):
        VStruct.__init__(self)
        self.Magic                       = vbytes(size=2)
        self.MajorLinkerVersion          = uint8()
        self.MinorLinkerVersion          = uint8()
        self.SizeOfCode                  = uint32()
        self.SizeOfInitializedData       = uint32()
        self.SizeOfUninitializedData     = uint32()
        self.AddressOfEntryPoint         = uint32()
        self.BaseOfCode                  = uint32()
        self.ImageBase                   = uint64()
        self.SectionAlignment            = uint32()
        self.FileAlignment               = uint32()
        self.MajorOperatingSystemVersion = uint16()
        self.MinorOperatingSystemVersion = uint16()
        self.MajorImageVersion           = uint16()
        self.MinorImageVersion           = uint16()
        self.MajorSubsystemVersion       = uint16()
        self.MinorSubsystemVersion       = uint16()
        self.Win32VersionValue           = uint32()
        self.SizeOfImage                 = uint32()
        self.SizeOfHeaders               = uint32()
        self.CheckSum                    = uint32()
        self.Subsystem                   = uint16()
        self.DllCharacteristics          = uint16()
        self.SizeOfStackReserve          = uint64()
        self.SizeOfStackCommit           = uint64()
        self.SizeOfHeapReserve           = uint64()
        self.SizeOfHeapCommit            = uint64()
        self.LoaderFlags                 = uint32()
        self.NumberOfRvaAndSizes         = uint32()
        self.DataDirectory               = VArray([IMAGE_DATA_DIRECTORY() for i in range(16)])

class IMAGE_RESOURCE_DIRECTORY(VStruct):
    def __init__(self):
        VStruct.__init__(self)
        self.Characteristics      = uint32()
        self.TimeDateStamp        = uint32()
        self.MajorVersion         = uint16()
        self.MinorVersion         = uint16()
        self.NumberOfNamedEntries = uint16()
        self.NumberOfIdEntries    = uint16()

class IMAGE_RESOURCE_DIRECTORY_ENTRY(VStruct):
    def __init__(self):
        VStruct.__init__(self)
        self.Name           = uint32()
        self.OffsetToData   = uint32()

class IMAGE_RESOURCE_DATA_ENTRY(VStruct):
    def __init__(self):
        VStruct.__init__(self)
        self.OffsetToData   = uint32()
        self.Size           = uint32()
        self.CodePage       = uint32()
        self.Reserved       = uint32()

class VS_FIXEDFILEINFO(VStruct):
    def __init__(self):
        VStruct.__init__(self)
        self.Signature          = uint32()
        self.StrucVersion       = uint32()
        self.FileVersionMS      = uint32()
        self.FileVersionLS      = uint32()
        self.ProductVersionMS   = uint32()
        self.ProductVersionLS   = uint32()
        self.FileFlagsMask      = uint32()
        self.FileFlags          = uint32()
        self.FileOS             = uint32()
        self.FileType           = uint32()
        self.FileSubtype        = uint32()
        self.FileDateMS         = uint32()
        self.FileDateLS         = uint32()

class IMAGE_SECTION_HEADER(VStruct):

    def __init__(self):
        VStruct.__init__(self)
        self.Name                 = cstr(size=8)
        self.VirtualSize          = uint32()
        self.VirtualAddress       = uint32()
        self.SizeOfRawData        = uint32()
        self.PointerToRawData     = uint32()
        self.PointerToRelocations = uint32()
        self.PointerToLineNumbers = uint32()
        self.NumberOfRelocations  = uint16()
        self.NumberOfLineNumbers  = uint16()
        self.Characteristics      = uint32()


class IMAGE_RUNTIME_FUNCTION_ENTRY(VStruct):
    """
    Used in the .pdata section of a PE32+ for all non
    leaf functions.
    """
    def __init__(self):
        VStruct.__init__(self)
        self.BeginAddress = uint32()
        self.EndAddress = uint32()
        self.UnwindInfoAddress = uint32()

class UNWIND_INFO(VStruct):
    def __init__(self):
        VStruct.__init__(self)
        self.VerFlags       = uint8()
        self.SizeOfProlog   = uint8()
        self.CountOfCodes   = uint8()
        self.FrameRegister  = uint8()

class SignatureEntry(VStruct):

    def __init__(self):
        VStruct.__init__(self)
        self.size = int32(bigend=False).vsOnSet( self._onSetSize )
        self.magic = vbytes(size=4) # should always be 0x00020200
        self.pkcs7 = vbytes()

    def _onSetSize(self, valu):
        self['pkcs7'].vsResize(valu)

class PeLab(BexLab):

    def __init__(self, fd, off=0):

        BexLab.__init__(self, fd, off=off)

        dos = self.getStruct(self.off,IMAGE_DOS_HEADER)
        nt = self.getStruct(self.off + dos.e_lfanew, IMAGE_NT_HEADERS)

        if nt.FileHeader.Machine in (IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_IA64):
            nt = self.getStruct( dos.e_lfanew, IMAGE_NT_HEADERS64)

        # set up some of the generic binary executable fields

        self.set('pe:IMAGE_DOS_HEADER', dos )
        self.set('pe:IMAGE_NT_HEADERS', nt )

        self.set('bex:arch', machine_names.get(nt.FileHeader.Machine))
        self.set('bex:ptr:size', machine_ptr_sizes.get(nt.FileHeader.Machine))
        self.set('bex:ptr:base', nt.OptionalHeader.ImageBase )

        # add on-demand parsers for additional fields
        self.add('pe:dllname', self._getPeDllName)
        self.add('pe:IMAGE_EXPORT_DIRECTORY', self._getPeExpDir )

        self.add('pe:sections', self._getPeSects )
        self.add('pe:sections:byname', self._getPeSectsByName )

        self.add('bex:mem:maps', self._getMemMaps )
        #self.add('bex:mem:secs', self._getMemSecs )
        #self.add('bex:imports', self._getPeImports )

    def getSectByName(self, name):
        '''
        Return an IMAGE_SECTION_HEADER by name.

        Example:

            sect = plab.getSectByName('.relocs')

        '''
        return self.get('pe:sections:byname').get(name)

    def _getPeDllName(self):

        edir = self.get('pe:IMAGE_EXPORT_DIRECTORY')
        if edir == None:
            return None

        off = self.rvaToOff(edir.Name)
        if off == None:
            return None

        return self.strAtOff(off)

    def _getPeExpDir(self):
        nt = self.get('pe:IMAGE_NT_HEADERS')
        edir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
        if edir.VirtualAddress == 0:
            return None

        eoff = self.rvaToOff(edir.VirtualAddress)
        if eoff == None:
            return None

        return self.getStruct(eoff,IMAGE_EXPORT_DIRECTORY)

    def _getPeSects(self):
        dos = self.get('pe:IMAGE_DOS_HEADER')
        nt = self.get('pe:IMAGE_NT_HEADERS')

        off = dos.e_lfanew + len(nt)
        scls = varray(nt.FileHeader.NumberOfSections, IMAGE_SECTION_HEADER)
        return self.getStruct(off,scls)

    def _getPeSectsByName(self):
        return { s.Name:s for (i,s) in self.get('pe:sections') }

    def _getMemMaps(self):
        maps = [ (0, {'size':4096,'off':0}), ]
        for indx,sect in self.get('pe:sections'):
            mmap = (sect.VirtualAddress, {'size':sect.VirtualSize,'off':sect.PointerToRawData})
            maps.append(mmap)
        return  maps

def isMimePe(fd):

    dos = IMAGE_DOS_HEADER()
    dos.vsLoad(fd,offset=0)

    if dos.e_magic != DOS_MAGIC:
        return False

    nt = IMAGE_NT_HEADERS()
    nt.vsLoad(fd, offset=dos.e_lfanew)

    return nt.Signature[:2] == b'PE'
