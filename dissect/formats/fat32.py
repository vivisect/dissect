'''
FAT32 file system structures. Read-write FAT32 file system driver.
'''
import os
import math
import logging
import functools

import vstruct.types as v_types

import dissect.formats.mbr as mbr


logger = logging.getLogger(__name__)


class FileExistsException(Exception):
    pass


class FileDoesNotExistException(Exception):
    pass


class IllegalArgumentException(ValueError):
    pass


# size of an entry in the FAT32 directory data
FILE_ENTRY_SIZE = 0x20

# size of an entry in the FAT32 file allocation table
FAT_ENTRY_SIZE = 0x4

# mask of usable bits in a file allocation table entry
FAT_ENTRY_MASK = 0x0FFFFFFF

# flag for tagging the last LONG_NAME directory entry
LAST_LONG_ENTRY = 0x40

# the number of bytes reserved for 8.3 filenames
DIR_NAME_SIZE = 11


# reserved file allocation table entry values.
# via: http://www.ntfs.com/fat-allocation.htm
CLUSTER_TYPES = v_types.venum()
CLUSTER_TYPES.UNUSED = 0x0
CLUSTER_TYPES.BAD = 0xFFFFFFF7 & FAT_ENTRY_MASK
CLUSTER_TYPES.LAST = 0xFFFFFFF8 & FAT_ENTRY_MASK

# directory entry attributes. bit flags.
DIRECTORY_ATTRIBUTES = v_types.venum()
DIRECTORY_ATTRIBUTES.ATTR_READ_ONLY = 0x1
DIRECTORY_ATTRIBUTES.ATTR_HIDDEN = 0x2
DIRECTORY_ATTRIBUTES.ATTR_SYSTEM = 0x4
DIRECTORY_ATTRIBUTES.ATTR_VOLUME_ID = 0x8
DIRECTORY_ATTRIBUTES.ATTR_DIRECTORY = 0x10
DIRECTORY_ATTRIBUTES.ATTR_ARCHIVE = 0x20
DIRECTORY_ATTRIBUTES.ATTR_LONG_NAME = DIRECTORY_ATTRIBUTES.ATTR_READ_ONLY | \
        DIRECTORY_ATTRIBUTES.ATTR_HIDDEN | \
        DIRECTORY_ATTRIBUTES.ATTR_SYSTEM | \
        DIRECTORY_ATTRIBUTES.ATTR_VOLUME_ID

# The following characters are not legal in any bytes of DIR_Name
#  - Values less than 0x20 except for the special case of 0x05 in DIR_Name[0] described above.
#  - 0x22, 0x2A, 0x2B, 0x2C, 0x2E, 0x2F, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x5B, 0x5C, 0x5D, 0x7C
# via: https://staff.washington.edu/dittrich/misc/fatgen103.pdf
ILLEGAL_83_CHARS = ''.join([chr(c) for c in range(0x20) if c != 0x5]) + \
        '\x22\x2A\x2B\x2C\x2E\x2F\x3A\x3B\x3C\x3D\x3E\x3F\x5B\x5C\x5D\x7C'


class CorruptFileSystemError(Exception):
    '''
    an error occured while parsing existing structures from the file system.
    '''
    pass


class DiskFullException(Exception):
    pass


class DirectoryDataIsFullException(ValueError):
    '''
    non-critical error that should be handled by this module.
    '''
    pass


class DirectoryNotEmptyException(ValueError):
    '''
    an error raised when a directory is deleted when it contains at least
      one file or subdirectory.
    '''
    pass


def cast_vstruct(src_instance, dst_instance):
    '''
    load the bytes that back `src_instance` into `dst_instance`.
    note that subsequent changes made to `dst_instance` are not reflected in `src_instance`.
    so this is useful in 'by-value' situations, but not for situations expecting writeback support.
    modifies `dst_instance`. does not modify src_instance.


    type src_instance: v_types.VStruct

    type dst_instance: v_types.VStruct
    '''
    d = src_instance.vsEmit()
    dst_instance.vsParse(d)


# via: https://staff.washington.edu/dittrich/misc/fatgen103.pdf
class BIOS_PARAMETER_BLOCK_FAT32(v_types.VStruct):
    '''
    always found at the first logical sector of the FAT32 file system.
    a backup instance is often found at logical sector 6.

    specifies the geometry of the file system, including things like:
      - cluster size
      - locations of data structures
      - file system label
    '''
    def __init__(self):
        super(BIOS_PARAMETER_BLOCK_FAT32, self).__init__()
        # for interpretation of these fields, please see:
        #  https://staff.washington.edu/dittrich/misc/fatgen103.pdf
        self.BPB_jmpBoot = v_types.vbytes(size=3)
        self.BPB_OEMName = v_types.vbytes(size=8)
        self.BPB_BytsPerSec = v_types.uint16()
        self.BPB_SecPerClus = v_types.uint8()
        self.BPB_RsvdSecCnt = v_types.uint16()
        self.BPB_NumFATs = v_types.uint8()
        self.BPB_RootEntCnt = v_types.uint16()
        self.BPB_TotSec16 = v_types.uint16()
        self.BPB_Media = v_types.uint8()
        self.BPB_FATSz16 = v_types.uint16()
        self.BPB_SecPerTrk = v_types.uint16()
        self.BPB_NumHeads = v_types.uint16()
        self.BPB_HiddSec = v_types.uint32()
        self.BPB_TotSec32 = v_types.uint32()

        # begin FAT32-specific fields
        # offset 36
        self.BPB_FATSz32 = v_types.uint32()
        self.BPB_ExtFlags = v_types.uint16()
        self.BPB_FSVer = v_types.uint16()
        self.BPB_RootClus = v_types.uint32()
        self.BPB_FSInfo = v_types.uint16()
        self.BPB_BkBootSec = v_types.uint16()
        self.BPB_Reserved = v_types.vbytes(size=12)
        self.BPB_DrvNum = v_types.uint8()
        self.BPB_Reserved1 = v_types.uint8()
        self.BPB_BootSig = v_types.uint8()
        self.BPB_VolID = v_types.uint32()
        self.BPB_VolLab = v_types.vbytes(size=11)
        self.BPB_FilSysType = v_types.vbytes(size=8)
        self.BPB_BootCode = v_types.vbytes(size=420)
        self.EndOfSectorMarker = v_types.uint16()


# via: https://staff.washington.edu/dittrich/misc/fatgen103.pdf
class FS_INFO(v_types.VStruct):
    '''
    provides hints to the file system driver that help optimize performance.
    these values *may* be incorrect, and drivers should continue to function.
    '''
    def __init__(self, should_validate=True):
        '''
        param should_validate: if True, validate fields and signatures to detect corruption.
        type should_validate: bool
        '''
        super(FS_INFO, self).__init__()
        # for interpretation of these fields, please see:
        #  https://staff.washington.edu/dittrich/misc/fatgen103.pdf
        self.FSI_LeadSig = v_types.uint32()
        self.FSI_Reserved1 = v_types.vbytes(size=480)
        self.FSI_StrucSig = v_types.uint32()
        self.FSI_Free_Count = v_types.uint32()
        self.FSI_Nxt_Free = v_types.uint32()
        self.FSI_Reserved2 = v_types.vbytes(size=12)
        self.FSI_TailSig = v_types.uint32()
        if should_validate:
            self['FSI_TailSig'].vsOnset(self._validate)

    def _validate(self):
        if self.FSI_LeadSig != 0x41615252:
            raise CorruptFileSystemError('invalid FS_INFO LeadSig')
        if self.FSI_StrucSig != 0x61417272:
            raise CorruptFileSystemError('invalid FS_INFO StrucSig')
        if self.FSI_TailSig != 0xAA550000:
            raise CorruptFileSystemError('invalid FS_INFO TailSig')


LAST_CLUSTER_CHAIN_ENTRIES = (CLUSTER_TYPES.UNUSED, CLUSTER_TYPES.BAD, CLUSTER_TYPES.LAST)
             

class FILE_ALLOCATION_TABLE(v_types.VArray):
    '''
    key datastructure of FAT32. defines the allocation state of each
     cluster in the file system. also, defines logical data runs made
     up of possibly non-contiguous clusters.

    each entry in the table is 32bits long. there are a few reserved values.
     the remaining values are FAT table entry numbers that describe the next
     cluster in the chain.

    a cluster chain is a singly-linked list of cluster numbers that
     is extracted from this allocation table. fetching the content of
     the clusters in this chain yields a logical data run.

    example:
      cluster chain: 10, 13, 14, 16, 17, LAST

        +------------+
        | 10:  13    | --.
        +------------+   |
        | 11   UNUSED|   |
        +------------+   |
        | 12   UNUSED|   |
        +------------+ <-+
        | 13   14    | --.
        +------------+ <-+
        | 14   16    | --.
        +------------+   |
        | 15   UNUSED|   |
        +------------+ <-+
        | 16   17    | --.
        +------------+ <-+
        | 17   LAST  |
        +------------+
    '''
    def __init__(self, num_entries):
        '''
        param num_entries: the total number of clusters in the file system.
        type num_entries: int
        '''
        super(FILE_ALLOCATION_TABLE, self).__init__(fields=[v_types.uint32() for i in range(num_entries)])
        self[num_entries - 1].vsOnset(self._validate)

    def _validate(self):
        if int(self[0]) & 0x70000000 != 0:
            raise CorruptFileSystemError('invalid FAT endian signature')
        if int(self[1]) & 0x70000000 != 0:
            raise CorruptFileSystemError('invalid FAT endian signature run')

    def getClusterChain(self, start_cluster_num):
        '''
        get a list of integers that specify the cluster indexes that make up a cluster run.
        the last entry will always be a CLUSTER_TYPES value, or something is wrong.
        CLUSTER_TYPES.LAST is expected, the remainders are probably errors.


        param start_cluster_number: the first cluster number in the chain
        type start_cluster_number: int

        rtype: Sequence[int]
        '''
        ret = []
        entry = start_cluster_num & FAT_ENTRY_MASK
        while True:
            if entry >= CLUSTER_TYPES.LAST:
                entry = CLUSTER_TYPES.LAST

            ret.append(entry)
            if entry in LAST_CLUSTER_CHAIN_ENTRIES:
                break

            nxt = self[entry]
            if nxt is None:
                raise IndexError('FAT does not have requested entry')
            entry = int(nxt) & FAT_ENTRY_MASK

        return ret


# via: https://staff.washington.edu/dittrich/misc/fatgen103.pdf
class DIRECTORY_ENTRY(v_types.VStruct):
    '''
    single entry in a directory data run.
    length is 32 bytes on FAT32.
    '''
    def __init__(self):
        super(DIRECTORY_ENTRY, self).__init__()
        # 8 bytes of ASCII for the basename, 3 bytes for the extension.
        # period is implicit. left-justified, space padded.
        self.DIR_Name = v_types.vbytes(size=DIR_NAME_SIZE)
        self.DIR_Attr = v_types.uint8(enum=DIRECTORY_ATTRIBUTES)
        self.DIR_NTRes = v_types.vbytes(size=1)
        self.DIR_CrtTimeTenth = v_types.vbytes(size=1)
        self.DIR_CrtTime = v_types.vbytes(size=2)
        self.DIR_CrtDate = v_types.vbytes(size=2)
        self.DIR_LstAccDate = v_types.vbytes(size=2)
        self.DIR_FstClusHI = v_types.uint16()
        self.DIR_WrtTime = v_types.vbytes(size=2)
        self.DIR_WrtDate = v_types.vbytes(size=2)
        self.DIR_FstClusLO = v_types.uint16()
        self.DIR_FileSize = v_types.uint32()

    @property
    def is_free(self):
        '''
        is this directory entry currently in use?
        '''
        return self.DIR_Name[0] in (0x00, 0xE5)

    @property
    def is_long_name(self):
        '''
        is this directory entry actually a LONG_DIRECTORY_ENTRY?
        if so, you should not interpret its contents using this structure.
        '''
        return self.DIR_Attr & DIRECTORY_ATTRIBUTES.ATTR_LONG_NAME == DIRECTORY_ATTRIBUTES.ATTR_LONG_NAME

    @property
    def name(self):
        '''
        reconstruct the 8.3 name for this directory entry.
        '''
        if self.is_free:
            return ''
        elif self.DIR_Name[0:4] == b'\xFF\xFF\xFF\xFF':
            return ''
        else:
            name = self.DIR_Name[:0x8].rstrip(b' ')
            ext = self.DIR_Name[0x8:].rstrip(b' ')
            if len(ext) > 0:
                return (name + b'.' + ext).decode('ascii').partition('\x00')[0]
            else:
                return name.decode('ascii').partition('\x00')[0]

    @property
    def first_cluster(self):
        '''
        get the local cluster number of the data for this entry.

        rtype: int
        '''
        return (self.DIR_FstClusHI << 16) | self.DIR_FstClusLO

    def __str__(self):
        if self.is_free:
            return 'DIRECTORY_ENTRY (free)'
        elif self.is_long_name:
            return 'DIRECTORY_ENTRY (long name)'
        else:
            return 'DIRECTORY_ENTRY (name: %s)' % (self.name)


# via: https://staff.washington.edu/dittrich/misc/fatgen103.pdf
class LONG_DIRECTORY_ENTRY(v_types.VStruct):
    '''
    implements the FAT32 hack for supporting long names.
    reuses fields from a DIRECTORY_ENTRY to store 13 UTF-16LE bytes from
      a long name.
    it *must* have the LDIR_Attr equal to ATTR_LONG_NAME.
    '''
    def __init__(self):
        super(LONG_DIRECTORY_ENTRY, self).__init__()
        self.LDIR_Ord = v_types.uint8()
        self.LDIR_Name1 = v_types.vbytes(size=10)
        self.LDIR_Attr = v_types.uint8(enum=DIRECTORY_ATTRIBUTES)
        self.LDIR_Type = v_types.uint8()
        self.LDIR_Chksum = v_types.uint8()
        self.LDIR_Name2 = v_types.vbytes(size=12)
        self.LDIR_FstClusLO = v_types.uint16()
        self.LDIR_Name3 = v_types.vbytes(size=4).vsOnset(self._validate)

    def _validate(self):
        if self.LDIR_FstClusLO != 0:
            raise CorruptFileSystemError('bad LDIR_FstClusLO')
        if self.LDIR_Attr != DIRECTORY_ATTRIBUTES.ATTR_LONG_NAME:
            raise CorruptFileSystemError('bad directory entry attributes')

    @property
    def name_fragment(self):
        '''
        the part of the long name stored in this long directory entry.
        '''
        return self.LDIR_Name1 + self.LDIR_Name2 + self.LDIR_Name3

    @property
    def is_free(self):
        '''
        is this directory entry currently in use?
        '''
        return self.LDIR_Ord in (0x0, 0xE5)

    def __str__(self):
        if self.is_free:
            return 'LONG_DIRECTORY_ENTRY (free)'
        else:
            n = self.name_fragment.rstrip(b'\xFF').partition(b'\x00\x00\x00')[0]
            if len(n) % 2 != 0:
                n += b'\x00'
            return 'LONG_DIRECTORY_ENTRY (fragment: %s)' % (n.decode('utf-16le'))


class DIRECTORY_DATA(v_types.VArray):
    '''
    On disk, a sequence of DIRECTORY_ENTRYs. Conceptually, a list of child entries for
     a directory, which may include LONG_DIRECTORY_ENTRY items that describe non-8.3 filenames.
    '''
    def __init__(self, num_entries):
        '''
        param num_entries: the number of DIRECTORY_ENTRYs that should be found in this region.
        type num_entries: int
        '''
        super(DIRECTORY_DATA, self).__init__(fields=[DIRECTORY_ENTRY() for _ in range(num_entries)])
        self.num_entries = num_entries

    @staticmethod
    def _reconstructLongName(entries):
        '''
        from a list of LONG_DIRECTORY_ENTRYs, reconstruct the full long name of the entry.


        type entries: List[DIRECTORY_ENTRY]

        rtype: unicode
        '''
        # each LONG_DIRECTORY_ENTRY contains a hash of the associated 8.3 filename.
        # all these hashes should be the same, so track and verify this.
        hashes = set([])
        # list of strings of the name fragments extracted from the LONG_DIRECTORY_ENTRYs
        name_fragments = []

        # name fragments are stored in reverse order, and we want to process
        # from the start of the name to the end
        for entry in reversed(entries):
            # although we get DIRECTORY_ENTRYs,
            # we need to interpret the data as LONG_DIRECTORY_ENTRYs
            lentry = LONG_DIRECTORY_ENTRY()
            cast_vstruct(entry, lentry)
            name_fragments.append(lentry.name_fragment)
            hashes.add(lentry.LDIR_Chksum)

        if len(hashes) > 1:
            raise CorruptFileSystemError('invalid long name entry checksum')

        long_name = b''.join(name_fragments)
        # there may be, but not always, padding of \xFF\xFF
        # long names are always utf-16le
        long_name = long_name.partition(b'\xFF\xFF')[0].decode('utf-16le').rstrip('\x00')
        return long_name

    @property
    def entries(self):
        '''
        the DIRECTORY_ENTRYs in this DIRECTORY_DATA.

        rtype: Sequence[DIRECTORY_ENTRY]
        '''
        for i in range(self.num_entries):
            yield self[i]

    @property
    def is_full(self):
        '''
        are all entries in this DIRECTORY_DATA allocated and non-free?

        rtype: bool
        '''
        for entry in self.entries:
            if entry.is_free:
                return False
        return True

    @property
    def is_empty(self):
        '''
        does this DIRECTORY_DATA contain no files or directories?

        rtype: bool
        '''
        for entry in self.entries:
            if isinstance(entry, LONG_DIRECTORY_ENTRY) or entry.is_long_name:
                continue

            if not entry.is_free:
                if entry.name in ('.', '..'):
                    continue
                return False
        return True

    def getEmptySlots(self, count):
        '''
        get list of `count` contiguous empty slots in the directory data.


        type count: int

        rtype: Sequence[int]
        '''
        slots = []
        for i in range(self.num_entries):
            entry = self[i]
            if entry.is_free:
                slots.append(i)

                if len(slots) == count:
                    return slots

            elif len(slots) > 0:
                # reset list of slots, since we don't have enough contiguous
                slots = []

        raise DirectoryDataIsFullException()

    def _gen83Name(self, full_name, hint=None):
        '''
        format a name, and optionally a hint, using a modified 8.3 short
         filename generation algorithm.
        there is no standardized algorithm, so we have some leeway.
        but, its nice to be similar to existing drivers.
        inspired by: https://en.wikipedia.org/wiki/8.3_filename


        param full_name: the long name from which to generate the 8.3 name
        type full_name: unicode

        param hint: a suggested postfix number that probably won't conflict
         with other names in the directory
        type hint: int

        rtype: str
        '''
        if full_name in ('.', '..'):
            return full_name.ljust(DIR_NAME_SIZE, ' ')

        full_name = full_name.lstrip('.')

        if '.' in full_name:
            name, _, ext = full_name.rpartition('.')
        else:
            name = full_name
            ext = ''

        for char in ILLEGAL_83_CHARS:
            # yeah this is not fast. but it should be fast enough.
            name = name.replace(char, '')

        # truncate the extension, upper case it, and right pad it with spaces
        ext = ext[:3].upper().ljust(3, ' ')

        if len(name) > 8 or hint is not None:
            # inspired by: https://en.wikipedia.org/wiki/8.3_filename
            # if name is too long (or there's a conflict we need to resolve),
            # take (about) the first six characters, then tilde, then a number
            # finally, uppercase, and right pad with spaces
            shint = str(hint or 0)
            name = (name[:7 - len(shint)] + '~' + shint).upper().ljust(8, ' ')
        else:
            # names with 8 or less characters are uppercased and right padded with spaces
            name = name.upper().ljust(8, ' ')

        return name + ext

    def _genNext83Name(self, full_name):
        '''
        Generate an 8.3 filename that doesn't conflict with files in this directory.
        Keeps trying to append incrementing numbers to the shortened basename until it works.
        There might be pathological cases.


        type full_name: unicode
        rtype: str
        '''
        short_name = self._gen83Name(full_name)
        # get the current list of names, so we can ensure we don't conflict.
        # need to use this madness because of the embedded period thats not actually stored
        # but we are including in entry.name
        names = set([])
        for entry in self.entries:
            if entry.is_free:
                continue
            if isinstance(entry, LONG_DIRECTORY_ENTRY) or entry.is_long_name:
                continue
            names.add(entry.DIR_Name.decode('ascii'))

        if short_name in names:
            hint = 0
            while short_name in names:
                short_name = self._gen83Name(full_name, hint=hint)
                hint += 1
        return short_name

    @staticmethod
    def compute83Hash(short_name):
        '''
        additive bytewise ROR
        via: http://staff.washington.edu/dittrich/misc/fatgen103.pdf


        type short_name: str
        rtype: int
        '''
        sum = 0
        for c in short_name:
            d = ord(c)
            if sum & 1:
                sum = 0x80 + (sum >> 1) + d
            else:
                sum = (sum >> 1) + d
            sum &= 0xFF
        return sum

    def _genLongEntry(self, name_data, index, short_name_hash):
        '''
        from the given long name data and related data, construct a single LONG_DIRECTORY_ENTRY
         that need to be added to this DIRECTORY_DATA.


        param name_data: the raw bytes of the long name
        type name_data: bytes

        param index: the index of this LONG_DIRECTORY_ENTRY in the sequence of entries for the long name
        type index: int

        param short_name_hash: the hash of the associated 8.3 short name
        type short_name_hash: int

        rtype: LONG_DIRECTORY_ENTRY
        '''
        # long entry indexes start from on
        # via: https://staff.washington.edu/dittrich/misc/fatgen103.pdf page 28
        if index == 0:
            raise IllegalArgumentException('LONG_ENTRY indexes start at 1')

        # 13 chars per entry
        # 255 max number of chars in path component
        # == 19 max number of entries, 0x13 in hex
        if index > 0x13:
            raise IllegalArgumentException('LONG_ENTRY index too large')

        entry = LONG_DIRECTORY_ENTRY()
        entry.LDIR_Ord = index
        entry.LDIR_Chksum = short_name_hash
        entry.LDIR_Attr = DIRECTORY_ATTRIBUTES.ATTR_LONG_NAME
        entry.LDIR_Name1 = name_data[:10]
        entry.LDIR_Name2 = name_data[10:10+12]
        entry.LDIR_Name3 = name_data[22:22+4]
        return entry

    def _genLongEntries(self, long_name, short_name):
        '''
        from given short and long names, compute the sequence of LONG_DIRECTORY_ENTRYs
         that need to be added to this DIRECTORY_DATA.


        param long_name: the long name
        type long_name: unicode

        param short_name: the associated short name
        type short_name: str

        rtype: Sequence[LONG_DIRECTORY_ENTRY]
        '''
        # the number of characters we can fit in each long entry
        chars_per_entry = 13

        # the number of bytes (that contain utf-16le characters) that we can use in each long entry
        useful_bytes_per_entry = 2 * chars_per_entry

        long_name_data = long_name.encode('utf-16le')
        # add the utf-16 NULL
        if len(long_name_data) % useful_bytes_per_entry != 0:
            long_name_data += 2 * b'\x00'

        # and then pad with 0xFFFFs
        if len(long_name_data) % useful_bytes_per_entry != 0:
            num_padding_bytes = useful_bytes_per_entry - (len(long_name_data) % useful_bytes_per_entry)
            long_name_data += b'\xFF' * num_padding_bytes

        short_name_hash = self.compute83Hash(short_name)

        entries = []
        for i, name_offset in enumerate(range(0, len(long_name_data), useful_bytes_per_entry)):
            # TODO: refactor chunks util function
            name_entry_data = long_name_data[name_offset:name_offset + useful_bytes_per_entry]
            entries.append(self._genLongEntry(name_entry_data, i + 1, short_name_hash))

        last_entry = entries[-1]
        last_entry.LDIR_Ord = int(last_entry.LDIR_Ord) | LAST_LONG_ENTRY

        return reversed(entries)

    def _genEntries(self, name, cluster_number, flags=0, size=0):
        '''
        from given name and data location, compute the sequence
         of DIRECTORY_ENTRY and LONG_DIRECTORY_ENTRYs that need to be
         added to this DIRECTORY_DATA.


        param name: the name of the entry to add
        type name: unicode

        param cluster_number: the location of the data referenced by the entries
        type cluster_number: int

        param flags: the attributes entries, probably ATTR_DIRECTORY for directories.
        type flags: int

        param size: the size of the file pointed to by the entry, if a file.
        type size: int

        rtype: Sequence[Union[LONG_DIRECTORY_ENTRY, DIRECTORY_ENTRY]]
        '''
        short_name = self._genNext83Name(name)

        entry = DIRECTORY_ENTRY()

        # explicit initialization of buffers, due to vstruct issue #3
        entry.DIR_Name = b'\x00' * DIR_NAME_SIZE
        entry.DIR_NTRes = b'\x00' * 1
        entry.DIR_CrtTimeTenth = b'\x00' * 1
        entry.DIR_CrtTime = b'\x00' * 2
        entry.DIR_CrtDate = b'\x00' * 2
        entry.DIR_LstAccDate = b'\x00' * 2
        entry.DIR_WrtTime = b'\x00' * 2
        entry.DIR_WrtDate = b'\x00' * 2

        entry.DIR_Name = short_name.encode('ascii')
        entry.DIR_Attr = flags
        entry.DIR_FstClusHI = (int(cluster_number) & 0xFFFF00) >> 16
        entry.DIR_FstClusLO = (int(cluster_number) & 0x00FFFF)
        entry.DIR_FileSize = size

        long_entries = self._genLongEntries(name, short_name)
        entries = list(long_entries) + [entry]

        return entries

    def addDirectoryEntry(self, name, cluster_number):
        '''
        add the necessary entries for a directory to this DIRECTORY_DATA for the given name and location.


        param name: the name of the subdirectory
        type name: unicode

        param cluster_number: the first cluster number in the cluster chain for
         the DIRECTORY_DATA for the subdirectory
        type cluster_number: int
        '''
        if self.is_full:
            raise DirectoryDataIsFullException()

        entries = self._genEntries(name, cluster_number, flags=DIRECTORY_ATTRIBUTES.ATTR_DIRECTORY)

        logger.debug('directory: add directory: name: %s start: %x', name, cluster_number)
        for i, entry in zip(self.getEmptySlots(len(entries)), entries):
            logger.debug('directory: add entry: slot: %d fragment: %s', i, str(entry))
            self[i] = entry

    def addFileEntry(self, name, size, cluster_number):
        '''
        add the necessary entries for a file to this DIRECTORY_DATA for the given name and location.


        param name: the name of the file
        type name: unicode

        param cluster_number: the first cluster number in the cluster chain for
         the content of the file
        type cluster_number: int
        '''
        if self.is_full:
            raise DirectoryDataIsFullException()

        logger.debug('directory: add file: name: %s len: %x  start: %x', name, size, cluster_number)
        entries = self._genEntries(name, cluster_number, size=size)
        for i, entry in zip(self.getEmptySlots(len(entries)), entries):
            logger.debug('directory: add entry: slot: %d fragment: %s', i, str(entry))
            self[i] = entry

    def delEntry(self, name):
        '''
        remove the entries (including both DIRECTORY_ENTRY and LONG_DIRECTORY_ENTRY) associated
         with the given name.

        param name: the short or long name of the item to remove.
        type name: unicode
        '''
        # prior to an 8.3 named entry, there may be a sequence of long name entries
        # that contain the complete long of the same file
        # so if we find a long name, keep all the subsequent long names until the next 8.3 name
        indices_to_remove = []
        current_long_name_entries = []

        logger.debug('directory: del entry: name: %s', name)
        for i in range(self.num_entries):
            entry = self[i]

            if entry.is_free:
                continue

            if isinstance(entry, LONG_DIRECTORY_ENTRY) or entry.is_long_name:
                indices_to_remove.append(i)
                current_long_name_entries.append(entry)
                continue
            else:
                indices_to_remove.append(i)

            if entry.name == name or name == self._reconstructLongName(current_long_name_entries):
                for index in indices_to_remove:
                    logger.debug('directory: del index: index: %x', index)
                    self[index].DIR_Name = b'\xE5' + b'\x00' * (DIR_NAME_SIZE - 1)
                return
            else:
                # reset current long name and continue search
                indices_to_remove = []
                current_long_name_entries = []

        raise FileDoesNotExistException()

    def getEntriesAndLongNames(self):
        '''
        enumerate the tuples (DIRECTORY_ENTRY, long_name) for all the items in this directory.
        all the metadata for an item is found in the DIRECTORY_ENTRY, along with the 8.3 name.
        the long name may be present.

        rtype: Sequence[Tuple[DIRECTORY_ENTRY, unicode]]
        '''
        # prior to an 8.3 named entry, there may be a sequence of long name entries
        # that contain the complete long of the same file
        # so if we find a long name, keep all the subsequent long names until the next 8.3 name
        current_long_name_entries = []
        for entry in self.entries:
            if entry.is_free:
                continue

            if isinstance(entry, LONG_DIRECTORY_ENTRY) or entry.is_long_name:
                if isinstance(entry, LONG_DIRECTORY_ENTRY) and entry.LDIR_Ord & LAST_LONG_ENTRY:
                    current_long_name_entries = []
                if entry.DIR_Name[0] & LAST_LONG_ENTRY:
                    current_long_name_entries = []
                current_long_name_entries.append(entry)
                continue

            long_name = self._reconstructLongName(current_long_name_entries)
            current_long_name_entries = []

            yield entry, long_name


class Cluster(v_types.vbytes):
    '''
    a sequence of bytes with length equal to the file system cluster size
    '''
    def __init__(self, cluster_size):
        '''
        param cluster_size: the size of a cluster in bytes on the file system.
        '''
        super(Cluster, self).__init__(size=cluster_size)


class FAT32ClusterArray(v_types.VArray):
    '''
    an array of Clusters exposed on a FAT32 file system.
    the first two indexes are reserved.

    implementation note: since the first two clusters are invalid, they are
      vbytes with zero length. so they technically exist here, but don't give
      you any data.
    '''
    def __init__(self, cluster_size, count):
        '''
        param cluster_size: the size of a cluster in bytes on the file system.
        param count: the total number of clusters in the file system
        '''
        super(FAT32ClusterArray, self).__init__(fields=(
            # first two clusters are reserved, and should not be fetched/set
            [v_types.vbytes(0), v_types.vbytes(0)] + [Cluster(cluster_size) for _ in range(count-2)]))


class FAT32(v_types.VStruct):
    '''
    most of the FAT32 file system data structures, including:
      - BIOS_PARAMETER_BLOCK_FAT32 (and backup)
      - FILE_ALLOCATION_TABLE (all)
      - FS_INFO
      - ClusterArray

    there are intermediate 'unallocated' vbytes regions that represent the
     slack data between these structures.
    '''
    def __init__(self, is_new_fs):
        '''
        param is_new_fs: is the FS initialized? if not, disables parsing/verification of some structures.
        '''
        super(FAT32, self).__init__()
        # the only structure with a fixed address is the BPB, at sector 0.
        # the remainder are found at variable addresses described in the primary BPB.
        # so, we have to parse the BPB, figure out which other structures exist, and
        #  dynamically add them to this structure (also, fill in the slack spaces).
        self.bpb = BIOS_PARAMETER_BLOCK_FAT32()
        self.bpb['EndOfSectorMarker'].vsOnset(self._onBPBParsed)
        self._is_new_fs = is_new_fs

    def _onBPBParsed(self):
        # here's what we're going to do:
        #  1. figure out which structures exists
        #  2. their offsets and lengths
        #  3. sort these by starting offset
        #  4. compute the slack regions between pairs of structures
        #  5. finally, add the substructures as fields of this structure
        items = []

        # represents a FAT32 file system region, including its name, type, offset, and length.
        # enables the computation of allocated and slack regions across the partition.
        #
        # defined inline since its a utility struct, not used by any other functions.
        @functools.total_ordering
        class SubStructureDescriptor:
            def __init__(self, name, offset, length, item):
                self.name = name
                self.offset = offset
                self.length = length
                self.item = item

            # so we can use `sort`/`sorted`
            def __eq__(self, other):
                return self.name == other.name and \
                        self.offset == other.offset and \
                        self.length == other.length and \
                        self.item == other.item

            def __lt__(self, other):
                return self.offset < other.offset

        # add backup BPB, if it exists
        bpb_backup_offset = 0
        bpb_backup_size = 0
        if self.bpb.BPB_BkBootSec != 0:
            bpb_backup_offset = self.bpb.BPB_BkBootSec * mbr.SECTOR_SIZE
            bpb_backup_size = mbr.SECTOR_SIZE
        bpb_backup = SubStructureDescriptor('bpb_backup', bpb_backup_offset, bpb_backup_size,
                BIOS_PARAMETER_BLOCK_FAT32())
        items.append(bpb_backup)

        # add FS_INFO, if it exists
        fs_info_offset = 0
        fs_info_size = 0
        if self.bpb.BPB_FSInfo != 0:
            fs_info_offset = self.bpb.BPB_FSInfo * mbr.SECTOR_SIZE
            fs_info_size = mbr.SECTOR_SIZE
        fs_info = SubStructureDescriptor('fs_info', fs_info_offset, fs_info_size,
                FS_INFO(should_validate=not self._is_new_fs))
        items.append(fs_info)

        # add FATs, if the FS is initialized
        if self.bpb.BPB_RsvdSecCnt != 0:
            fat_sector_start = self.bpb.BPB_RsvdSecCnt
            for i in range(self.bpb.BPB_NumFATs):
                fat_start = fat_sector_start * mbr.SECTOR_SIZE
                fat_size = self.fat_size * mbr.SECTOR_SIZE
                fat = SubStructureDescriptor('fat_{:d}'.format(i), fat_start, fat_size,
                        FILE_ALLOCATION_TABLE(self.fat_entry_count))
                items.append(fat)
                fat_sector_start += fat_sector_start + self.fat_size

        # add cluster array, if the FS is initialized
        if not self._is_new_fs:
            clusters = SubStructureDescriptor('clusters',
                    self.clusters_offset * mbr.SECTOR_SIZE,
                    self.cluster_size * self.total_cluster_count,
                    FAT32ClusterArray(self.cluster_size, self.total_cluster_count))
            items.append(clusters)

        # exclude any zero-length items
        items = filter(lambda i: i.length != 0, items)

        # items naturally sort by starting offset
        items = sorted(items)

        # add unallocated regions and structures as fields
        index = 0
        current_offset = mbr.SECTOR_SIZE
        while len(items) > 0:
            item = items.pop(0)
            if item.offset != current_offset:
                diff_size = item.offset - current_offset
                if diff_size < 0:
                    raise CorruptFileSystemError('overlapping structures')

                unalloc = v_types.vbytes(size=diff_size)
                unalloc_name = 'unalloc_{:d}'.format(index)
                setattr(self, unalloc_name, unalloc)
                current_offset += diff_size

            setattr(self, item.name, item.item)
            index += 1
            current_offset += item.length

    @property
    def total_sector_count(self):
        '''
        total number of sectors in this file system.
        '''
        if self.bpb.BPB_TotSec16 != 0:
            return self.bpb.BPB_TotSec16
        else:
            return self.bpb.BPB_TotSec32

    @property
    def total_cluster_count(self):
        '''
        total number of clusters in this file system.
        '''
        return (self.total_sector_count - self.clusters_offset) // self.bpb.BPB_SecPerClus

    @property
    def fat_size(self):
        '''
        size of each allocation table in sectors.
        '''
        sz = self.bpb.BPB_FATSz16
        if sz == 0:
            sz = self.bpb.BPB_FATSz32
        if sz == 0:
            raise CorruptFileSystemError('invalid FAT size')
        return sz

    @property
    def fat_entry_count(self):
        '''
        number of entries in each allocation table.
        '''
        return (self.fat_size * mbr.SECTOR_SIZE) // FAT_ENTRY_SIZE

    @property
    def clusters_offset(self):
        '''
        offset in sectors of the start of the cluster array
        '''
        return self.bpb.BPB_RsvdSecCnt * (self.fat_size * self.bpb.BPB_NumFATs)

    @property
    def cluster_size(self):
        '''
        size of each cluster in bytes
        '''
        return self.bpb.BPB_SecPerClus * mbr.SECTOR_SIZE

    @property
    def empty_cluster(self):
        '''
        one cluster's worth of NULL bytes
        '''
        return b'\x00' * self.cluster_size

    @property
    def fats(self):
        '''
        sequence of the allocation tables in this file system
        '''
        for i in range(self.bpb.BPB_NumFATs):
            fat_name = 'fat_{:d}'.format(i)
            yield getattr(self, fat_name)

    def _getFatEntry(self, index):
        '''
        fetch the allocation table entry at the given index, validating the results
         against all allocation tables in this file system.
        '''
        values = set([])
        for f in self.fats:
            values.add(int(f[index]))
        if len(values) > 1:
            raise CorruptFileSystemError('conflicting FAT entries')
        return values.pop()

    def _setFatEntry(self, index, value):
        '''
        set the allocation table entry at the given index, mirroring the value
         across all allocation tables in this file system.
        '''
        logger.debug('fat: set fat entry: %x %x', index, value)
        for f in self.fats:
            f[index] = value

    def isClusterFree(self, i):
        '''
        is the given cluster allocated of free?
        '''
        return self._getFatEntry(i) == CLUSTER_TYPES.UNUSED

    def getFreeClusterNumber(self):
        '''
        get the first free cluster in the file system.
        '''
        for i in range(self.total_cluster_count):
            if self.isClusterFree(i):
                return i

    def markClusterFree(self, i):
        '''
        set a cluster as unallocated.
        '''
        logger.debug('fat: set entry free: %x', i)
        self._setFatEntry(i, CLUSTER_TYPES.UNUSED)

    def markClusterUsed(self, i, next_cluster=CLUSTER_TYPES.LAST):
        '''
        mark a cluster as part of a cluster chain.
        if `next_cluster` is provided then it is the next cluster number in the chain.
        otherwise, this is the last entry in the chain.
        '''
        logger.debug('fat: set entry used: %x', i)
        self._setFatEntry(i, next_cluster)

    def getClusterChain(self, cluster_num):
        '''
        fetch the cluster chain starting at the given cluster number.

        rtype: Sequence[int]
        '''
        chains = []
        for f in self.fats:
            chains.append(f.getClusterChain(cluster_num))

        if len(chains) > 1:
            s = set(chains[0])
            for other in chains[1:]:
                if len(s.difference(set(other))) > 0:
                    raise CorruptFileSystemError('fat cluster chain conflict')

        chain = chains[0]
        if CLUSTER_TYPES.BAD in chain:
            raise CorruptFileSystemError('bad cluster encountered')

        return chain

    def getContent(self, start_cluster_num):
        '''
        get the content of the cluster chain starting at the given cluster number.
        the length of the data returned is always a multiple of the cluster size.

        rtype: bytes
        '''
        if self.isClusterFree(start_cluster_num):
                raise FileDoesNotExistException()

        data = []
        for cluster_num in self.getClusterChain(start_cluster_num):
            if cluster_num == CLUSTER_TYPES.LAST:
                break
            data.append(bytes(self.clusters[cluster_num]))

        return b''.join(data)

    def setContent(self, start_cluster_num, data):
        '''
        set the contents to a cluster chain that starts at the given cluster number.

        this is the main allocation routine for the FAT32 driver.
        if the existing cluster chain at the given address is not large enough, this
         routine finds unallocated clusters and adds them to the chain.
        if the existing chain is too large, the extra clusters at the end of the chain
         are removed.
        the routine therefore modifies both the cluster contents and allocation table entries.

        the length of the data does not have to be a multiple of the cluster size,
         but if its not, this routine automatically pads the data with NULLs until the
         length is a cluster-multiple.
        '''
        # handle degenerate case of zero-length data
        # since the cluster chain layer doesn't store the logical data size,
        #  we can use our own junk data if we want.
        # so, we use a single null byte, because this makes the following logic cleaner
        if len(data) == 0:
            data = b'\x00'

        num_clusters_needed = int(math.ceil(len(data) / self.cluster_size))
        # essentially the cluster chain we'll use to store the data
        cluster_numbers = []

        logger.debug('fat: set content: start: %x len: %x', start_cluster_num, len(data))
        logger.debug('fat: set content: clusters needed: %x', num_clusters_needed)

        if self.isClusterFree(start_cluster_num):
            logger.debug('fat: set content: new allocation')
        else:
            logger.debug('fat: set content: existing allocation')
            cluster_chain = self.getClusterChain(start_cluster_num)

            # don't get confused by the final entry of the cluster chain, which is always a LAST entry
            while cluster_chain[-1] == CLUSTER_TYPES.LAST:
                cluster_chain.pop(-1)

            # reuse the existing chain as much as possible
            num_new_clusters_needed = num_clusters_needed - len(cluster_chain)
            cluster_numbers = cluster_chain[:min(num_clusters_needed, len(cluster_chain))]

            if num_new_clusters_needed < 0:
                # the existing cluster chain is longer than needed
                # so mark the tail entries as UNUSED, and the final as LAST
                logger.debug('fat: set content: clipping existing allocation: %x clusters', -num_new_clusters_needed)
                for i in range(num_new_clusters_needed, -1):
                    self.markClusterFree(cluster_chain[i])
                self.markClusterUsed(cluster_chain[num_new_clusters_needed], CLUSTER_TYPES.LAST)
                num_new_clusters_needed = 0

        logger.debug('fat: set content: needed clusters: %x', num_clusters_needed - len(cluster_numbers))
        # find `num_clusters_needed` count of free clusters by doing a simple scan.
        # this algorithm could be faster if we cached the list of free clusters somewhere.
        for i in range(2, self.total_cluster_count):
            if self._getFatEntry(i) == CLUSTER_TYPES.UNUSED:
                logger.debug('fat: set content: found free cluster: %x', i)
                cluster_numbers.append(i)

            if len(cluster_numbers) == num_clusters_needed:
                break

        if len(cluster_numbers) != num_clusters_needed:
            raise DiskFullException()

        # pad out the data to a cluster multiple, or subsequent APIs will get angry
        if len(data) % self.cluster_size != 0:
            data = data + b'\x00' * (self.cluster_size - (len(data) % self.cluster_size))

        # chunk the data into cluster-sized regions
        cluster_chunks = []
        for i, cluster_offset in enumerate(range(0, len(data), self.cluster_size)):
            cluster_chunk = data[cluster_offset:cluster_offset + self.cluster_size]
            cluster_chunks.append(cluster_chunk)

        # actually set the file's contents.
        # note that at this point, these clusters aren't actually allocated.
        # ...good thing we're not supporting concurrency
        for cluster_num, cluster_chunk in zip(cluster_numbers, cluster_chunks):
            logger.debug('fat: set content: set cluster: %x', cluster_num)
            self.clusters[cluster_num] = cluster_chunk

        # set the cluster chain in the file allocation table
        logger.debug('setting chain: ...')
        cur_cluster_num = cluster_numbers.pop(0)
        first_cluster_num = cur_cluster_num
        while len(cluster_numbers) > 0:
            self.markClusterUsed(cur_cluster_num, cluster_numbers[0])
            logger.debug('chain entry: %s %s' % (hex(cur_cluster_num), hex(cluster_numbers[0])))
            cur_cluster_num = cluster_numbers.pop(0)
        self.markClusterUsed(cur_cluster_num, CLUSTER_TYPES.LAST)

        return first_cluster_num

    def addContent(self, data):
        '''
        set the contents to a cluster chain starting at the first available cluster.
        returns the starting cluster number of the added data.

        rtype: int
        '''
        num = self.getFreeClusterNumber()
        logger.debug('add content: free cluster: %x len: %x', num, len(data))
        self.setContent(num, data)
        return num

    def delContent(self, start_cluster_number):
        '''
        deallocate the cluster chain starting at the given cluster number.
        modifies the allocation table, but does not touch cluster data.
        '''
        if self.isClusterFree(start_cluster_number):
            raise FileDoesNotExistException()

        for cluster_num in self.getClusterChain(start_cluster_number):
            if cluster_num == CLUSTER_TYPES.LAST:
                break
            self.markClusterFree(cluster_num)

    def getDirectoryData(self, start_cluster_number):
        '''
        get *a copy* of the directory data found in the cluster chain
         starting at the given cluster number.

        rtype: DIRECTORY_DATA
        '''
        run_data = self.getContent(start_cluster_number)
        num_entries = len(run_data) // FILE_ENTRY_SIZE
        if num_entries > 200:
            logger.debug('directory data: chain: %s', self.getClusterChain(start_cluster_number))
            logger.debug('directory data: start: %x len: %x num: %x', start_cluster_number, len(run_data), num_entries)
        dir_data = DIRECTORY_DATA(num_entries)
        dir_data.vsParse(run_data)
        return dir_data

    def setDirectoryData(self, start_cluster_number, dir_data):
        '''
        commit the directory data to the appropriate cluster chain

        type dir_data: DIRECTORY_DATA
        '''
        data = dir_data.vsEmit()
        self.setContent(start_cluster_num, data)


class File:
    '''
    represents a logical file on a FAT32 file system.
    it has a name, size, and contents.
    '''
    def __init__(self, fs, short_name, cluster_number, size, long_name=None):
        self._fs = fs
        self.short_name = short_name
        self.long_name = long_name
        self.cluster_number = cluster_number
        self.size = size

    def getContent(self):
        '''
        fetch the contents of the file from the file system.

        rtype: bytes
        '''
        return self._fs.getContent(self.cluster_number)[:self.size]

    def __str__(self):
        return 'File (name: %s)' % (self.long_name or self.short_name)


class Directory:
    '''
    represents a logical directory on a FAT32 file system.
    it has a name and children, including files and directories.
    '''
    def __init__(self, fs, short_name, cluster_number, long_name=None):
        self._fs = fs
        self.short_name = short_name
        self.long_name = long_name
        self.cluster_number = cluster_number

    @property
    def is_empty(self):
        '''
        does this directory have any children?
        '''
        dir_data = self._fs.getDirectoryData(self.cluster_number)
        return dir_data.is_empty

    def getSubDirectories(self):
        '''
        fetch the subdirectories of this directory.

        rtype: Directory
        '''
        dir_data = self._fs.getDirectoryData(self.cluster_number)
        for entry, long_name in dir_data.getEntriesAndLongNames():
            if not entry.DIR_Attr & DIRECTORY_ATTRIBUTES.ATTR_DIRECTORY:
                continue

            yield Directory(self._fs, entry.name, entry.first_cluster, long_name=long_name)

    def getFiles(self):
        '''
        fetch the files found within this directory.

        rtype: File
        '''
        dir_data = self._fs.getDirectoryData(self.cluster_number)
        for entry, long_name in dir_data.getEntriesAndLongNames():
            if entry.DIR_Attr & DIRECTORY_ATTRIBUTES.ATTR_DIRECTORY:
                continue

            yield File(self._fs, entry.name, entry.first_cluster, entry.DIR_FileSize, long_name=long_name)

    def __str__(self):
        return 'Directory (name: %s)' % (self.long_name or self.short_name)


class FAT32LogicalFileSystem:
    '''
    an API for easily listing, reading, writing, and creating files and directories
     on a FAT32 file system.
    while the FAT32 class has all the structures defined, this class
     implements the logic and algorithms for doing file system operations.

    note: this is not a vstruct.
    '''
    def __init__(self, fat):
        '''
        type fat: FAT32
        '''
        super(FAT32LogicalFileSystem, self).__init__()
        self._fat = fat

    def addFile(self, path, contents):
        '''
        create a file at the given path with the given contents.
        the file must not already exist.
        the path must be an absolute path.
        the parent directory must already exist.

        type path: unicode
        type contents: bytes
        '''
        parent = os.path.dirname(path)
        child = os.path.basename(path)

        parent_dir = self._getDirectory(parent)
        for d in parent_dir.getFiles():
            if d.short_name == child:
                raise FileExistsException()
            elif d.long_name == child:
                raise FileExistsException()

        child_cluster_number = self._fat.addContent(contents)

        parent_dir_data = None
        try:
            parent_dir_data = self._fat.getDirectoryData(parent_dir.cluster_number)
            parent_dir_data.addFileEntry(child, len(contents), child_cluster_number)
        except DirectoryDataIsFullException:
            self._growDirectoryData(parent_dir.cluster_number)
            parent_dir_data = self._fat.getDirectoryData(parent_dir.cluster_number)
            parent_dir_data.addFileEntry(child, len(contents), child_cluster_number)

        self._fat.setContent(parent_dir.cluster_number, parent_dir_data.vsEmit())
        self._fat.setContent(parent_dir.cluster_number, parent_dir_data.vsEmit())

    def delFile(self, path):
        '''
        delete the file at the given path.
        the file must already exist.
        the path must be an absolute path.

        type path: unicode
        '''
        parent = os.path.dirname(path)
        child = os.path.basename(path)

        child_entry = None
        parent_dir = self._getDirectory(parent)
        for f in parent_dir.getFiles():
            if f.short_name == child:
                child_entry = f
                break
            elif f.long_name == child:
                child_entry = f
                break
        if child_entry is None:
            raise FileDoesNotExistException()

        self._fat.delContent(child_entry.cluster_number)

        parent_dir_data = self._fat.getDirectoryData(parent_dir.cluster_number)
        parent_dir_data.delEntry(child)
        self._fat.setContent(parent_dir.cluster_number, parent_dir_data.vsEmit())

    def _getRootDir(self):
        '''
        get the Directory for the root directory of the file system.

        rtype: Directory
        '''
        root_clus = self._fat.bpb.BPB_RootClus
        return Directory(self._fat, '/', root_clus)

    def listFiles(self):
        '''
        enumerate the paths of all files on the file system.
        all paths are absolute paths.

        rtype: Sequence[unicode]
        '''
        def rec(directory, path_prefix='/'):
            for f in directory.getFiles():
                yield path_prefix + (f.long_name or f.short_name)

            for subdir in directory.getSubDirectories():
                if subdir.short_name in ('.', '..'):
                    continue

                yield from rec(subdir, path_prefix=path_prefix + (subdir.long_name or subdir.short_name) + '/')
        return rec(self._getRootDir())

    def readFile(self, path):
        '''
        fetch the contents of the file at the given directory.
        the path must be an absolute path.
        the path must exist.

        type path: unicode
        rtype: bytes
        '''
        def rec(directory, remaining_components):
            current_component = remaining_components[0]
            if len(remaining_components) == 1:
                for f in directory.getFiles():
                    if f.short_name == current_component:
                        return f
                    elif f.long_name == current_component:
                        return f
                raise FileDoesNotExistException()
            else:
                for d in directory.getSubDirectories():
                    if d.short_name == current_component:
                        return rec(d, remaining_components[1:])
                    elif d.long_name == current_component:
                        return rec(d, remaining_components[1:])
                raise FileDoesNotExistException()

        f = rec(self._getRootDir(), path.lstrip('/').split('/'))
        return f.getContent()

    def _getDirectory(self, path):
        '''
        fetch the Directory instance for the directory at the given path.

        type path: unicode
        rtype: Directory
        '''
        def rec(directory, remaining_components):
            current_component = remaining_components[0]
            if len(remaining_components) == 1:
                for d in directory.getSubDirectories():
                    if d.short_name == current_component:
                        return d
                    elif d.long_name == current_component:
                        return d
                raise FileDoesNotExistException()
            else:
                for d in directory.getSubDirectories():
                    if d.short_name == current_component:
                        return rec(d, remaining_components[1:])
                    elif d.long_name == current_component:
                        return rec(d, remaining_components[1:])
                raise FileDoesNotExistException()

        if path == '/':
            return self._getRootDir()
        return rec(self._getRootDir(), path.lstrip('/').split('/'))

    def _growDirectoryData(self, cluster_number):
        '''
        increase the size by one cluster of the data directory that starts at 
         the cluster chain beginning at the given cluste number.
        '''
        dir_data = self._fat.getDirectoryData(cluster_number)
        # allocate the directory entry, one cluster larger
        d = dir_data.vsEmit()
        d += self._fat.empty_cluster
        self._fat.setContent(cluster_number, d)

    def addDirectory(self, path):
        '''
        create the directory with the given path.
        the parent directory must already exist.
        the path must be an absolute path.
        the path must not already exist.

        type path: unicode
        '''
        parent = os.path.dirname(path)
        child = os.path.basename(path)

        parent_dir = self._getDirectory(parent)
        for d in parent_dir.getSubDirectories():
            if d.short_name == child:
                raise FileExistsException()
            elif d.long_name == child:
                raise FileExistsException()

        # allocate an initially empty directory data run of one cluster in length
        # and add the required dot entries to it
        child_cluster_number = self._fat.addContent(self._fat.empty_cluster)
        child_dir_data = self._fat.getDirectoryData(child_cluster_number)
        child_dir_data.addDirectoryEntry('.', child_cluster_number)
        child_dir_data.addDirectoryEntry('..', parent_dir.cluster_number)

        parent_dir_data = None
        try:
            parent_dir_data = self._fat.getDirectoryData(parent_dir.cluster_number)
            parent_dir_data.addDirectoryEntry(child, child_cluster_number)
        except DirectoryDataIsFullException:
            self._growDirectoryData(parent_dir.cluster_number)
            parent_dir_data = self._fat.getDirectoryData(parent_dir.cluster_number)
            parent_dir_data.addDirectoryEntry(child, child_cluster_number)

        self._fat.setContent(child_cluster_number, child_dir_data.vsEmit())
        self._fat.setContent(parent_dir.cluster_number, parent_dir_data.vsEmit())

    def delDirectory(self, path):
        '''
        delete the directory with the given path.
        the directory must exist.
        the directory must be empty.
        the path must be an absolute path.

        type path: unicode
        '''
        parent = os.path.dirname(path)
        child = os.path.basename(path)

        parent_dir = self._getDirectory(parent)
        child_dir = self._getDirectory(path)

        if not child_dir.is_empty:
            raise DirectoryNotEmptyException()

        self._fat.delContent(child_dir.cluster_number)

        parent_dir_data = self._fat.getDirectoryData(parent_dir.cluster_number)
        parent_dir_data.delEntry(child)
        self._fat.setContent(parent_dir.cluster_number, parent_dir_data.vsEmit())

    def listDirectories(self):
        '''
        enumerate the paths of all directories on the file system.
        all paths are absolute paths.

        rtype: Sequence[unicode]
        '''
        def rec(directory, path_prefix='/'):
            for subdir in directory.getSubDirectories():
                if subdir.short_name in ('.', '..'):
                    continue
                name = subdir.long_name or subdir.short_name
                yield path_prefix + name
                yield from rec(subdir, path_prefix=path_prefix + name + '/')
        return rec(self._getRootDir())

