'''
Structures useful for parsing an MS-DOS style MBR.
'''
import os
import math
import logging
import contextlib
import collections

import vstruct2.types as v_types


# assumption: sectors are 512-bytes in lenght
# anything other than this is... non-standard, and weird.
SECTOR_SIZE = 512


# partition types
SYSTEMID = v_types.venum()
SYSTEMID.EMPTY           = 0
SYSTEMID.FAT_12       = 1
SYSTEMID.XENIX_ROOT      = 2
SYSTEMID.XENIX_USR       = 3
SYSTEMID.FAT_16_INF32MB  = 4
SYSTEMID.EXTENDED        = 5
SYSTEMID.FAT_16          = 6
SYSTEMID.NTFS_HPFS       = 7
SYSTEMID.AIX             = 8
SYSTEMID.AIX_BOOT        = 9
SYSTEMID.OS2_BOOT_MGR    = 10
SYSTEMID.PRI_FAT32_INT13 = 11
SYSTEMID.EXT_FAT32_INT13 = 12
SYSTEMID.EXT_FAT16_INT13 = 14
SYSTEMID.WIN95_EXT       = 15
SYSTEMID.OPUS            = 16
SYSTEMID.FAT_12_HIDDEN   = 17
SYSTEMID.COMPAQ_DIAG     = 18
SYSTEMID.FAT_16_HIDDEN_INF32MB = 20
SYSTEMID.FAT_16_HIDDEN   = 22
SYSTEMID.NTFS_HPFS_HIDDEN= 23
SYSTEMID.VENIX           = 64
SYSTEMID.NOVEL0          = 81
SYSTEMID.MICROPORT       = 82
SYSTEMID.GNU_HURD        = 99
SYSTEMID.NOVEL1          = 100
SYSTEMID.PC_IX           = 117
SYSTEMID.MINUX_OLD       = 128
SYSTEMID.MINUX_LINUX     = 129
SYSTEMID.LINUX_SWAP      = 130
SYSTEMID.LINUX_NATIVE    = 131
SYSTEMID.AMOEBA          = 147
SYSTEMID.AMOEBA_BBT      = 148
SYSTEMID.BSD_386         = 165
SYSTEMID.BSDI_FS         = 183
SYSTEMID.BSDI_SWAP       = 184
SYSTEMID.SYRINX          = 199
SYSTEMID.CP_M            = 219
SYSTEMID.ACCESS_DOS      = 225
SYSTEMID.DOS_R_O         = 227
SYSTEMID.DOS_SECONDARY   = 242
SYSTEMID.BBT             = 255


# partition boot flag
BOOTINDICATOR = v_types.venum()
BOOTINDICATOR.NOBOOT = 0
BOOTINDICATOR.SYSTEM_PARTITION = 128


class PART_ENTRY(v_types.VStruct):
    '''
    partition entry in the MBR.
    '''
    def __init__(self):
        super(PART_ENTRY, self).__init__()
        self.BootIndicator = v_types.uint8(enum=BOOTINDICATOR)
        # can be set to zero to force LBA mode (access via sector offsets only)
        # via: https://en.wikipedia.org/wiki/Master_boot_record
        self.StartingHead = v_types.uint8()
        self.StartingSectCylinder = v_types.uint16()

        # partition type (but doesn't necessarily decl
        self.SystemID = v_types.uint8(enum=SYSTEMID)

        # can be set to zero to force LBA mode (access via sector offsets only)
        # via: https://en.wikipedia.org/wiki/Master_boot_record
        self.EndingHead = v_types.uint8()
        self.EndingSectCylinder = v_types.uint16()

        # offset to partition in sectors from start of disk
        self.RelativeSector = v_types.uint32()
        # size of partition in sectors
        self.TotalSectors = v_types.uint32()


class MASTER_BOOT_RECORD(v_types.VStruct):
    '''
    ... the MBR.
    '''
    def __init__(self):
        super(MASTER_BOOT_RECORD, self).__init__()
        self.BootCode = v_types.vbytes(size=446)
        self.Partitions = v_types.VArray(fields=[PART_ENTRY() for _ in range(4)])
        self.EndOfSectorMarker = v_types.uint16()


@contextlib.contextmanager
def MBR(path):
    '''
    Utility wrapper for MBR that makes it easily writable.

    example:
      with MBR('/dev/sda1') as mbr:
          mbr.BootCode = 'A' * SECTOR_SIZE
    '''
    with open(path, 'r+b') as f:
        mbr = MASTER_BOOT_RECORD()
        mbr.vsLoad(f, writeback=True)
        yield mbr
