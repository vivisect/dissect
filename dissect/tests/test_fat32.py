import os
import time
import logging
import unittest
import binascii
import contextlib

import dissect.mbr as mbr
import dissect.fat32 as fat32


TEST_IMAGE_PATH = "test.dd"
KILOBYTE = 1024
MEGABYTE = 1024 * KILOBYTE
GIGABYTE = 1024 * MEGABYTE
TERABYTE = 1024 * GIGABYTE
TEST_IMAGE_SIZE = 40 * MEGABYTE
TEST_PART_SIZE = 32 * MEGABYTE
MIN_FS_SIZE = 32 * MEGABYTE


# default linux no boot code
# prints something like, "this volume cannot be booted"
NOBOOT_CODE = bytes(binascii.unhexlify(b"""
0E 1F BE 77 7C AC
22 C0 74 0B 56 B4 0E BB  07 00 CD 10 5E EB F0 32
E4 CD 16 CD 19 EB FE 54  68 69 73 20 69 73 20 6E
6F 74 20 61 20 62 6F 6F  74 61 62 6C 65 20 64 69
73 6B 2E 20 20 50 6C 65  61 73 65 20 69 6E 73 65
72 74 20 61 20 62 6F 6F  74 61 62 6C 65 20 66 6C
6F 70 70 79 20 61 6E 64  0D 0A 70 72 65 73 73 20
61 6E 79 20 6B 65 79 20  74 6F 20 74 72 79 20 61
67 61 69 6E 20 2E 2E 2E  20 0D 0A""".lstrip(b"\x00").rstrip().replace(b" ", b"").replace(b"\n", b"")))


def set_first_partition_fat32(path, size):
    with mbr.MBR(path) as m :
        for i, _ in m.Partitions:
            part_entry = m.Partitions[i]
            if part_entry.TotalSectors != 0 or part_entry.RelativeSector != 0:
                raise RuntimeError("cannot update existing partition table with existing partitions")

        size_in_sectors = size // mbr.SECTOR_SIZE
        part_entry = m.Partitions[0]

        part_entry.BootIndicator = mbr.BOOTINDICATOR.NOBOOT
        # for CHS, can use zero, and for LBA mode
        # via: https://en.wikipedia.org/wiki/Master_boot_record
        part_entry.StartingHead = 0x0
        part_entry.StartingSectCylinder = 0x0
        part_entry.SystemID = mbr.SYSTEMID.PRI_FAT32_INT13
        part_entry.EndingHead = 0x0
        part_entry.EndingSectCylinder = 0x0
        part_entry.RelativeSector = 2048
        part_entry.TotalSectors = size_in_sectors

        m.EndOfSectorMarker = 0xAA55


def create_fat32_filesystem(path, partition_offset, size):
    if size < MIN_FS_SIZE:
        raise RuntimeError("min FAT32 file system size is 32MB (with 512 byte sectors)")

    fs = fat32.FAT32(True)
    with open(path, "r+b") as f:
        fs.vsLoad(f, partition_offset, writeback=True)

        fs.bpb.BPB_jmpBoot = b"\xEB\x58\x90"
        fs.bpb.BPB_OEMName = b"mkfs.fat"
        fs.bpb.BPB_BytsPerSec = mbr.SECTOR_SIZE

        # via: https://support.microsoft.com/en-us/kb/140365
        if size < 64 * MEGABYTE:
            fs.bpb.BPB_SecPerClus = 512 // mbr.SECTOR_SIZE
        elif 64 * MEGABYTE <= size < 128 * MEGABYTE:
            fs.bpb.BPB_SecPerClus = 1024 // mbr.SECTOR_SIZE
        elif 128 * MEGABYTE <= size < 256 * MEGABYTE:
            fs.bpb.BPB_SecPerClus = 2048 // mbr.SECTOR_SIZE
        elif 256 * MEGABYTE <= size < 8 * GIGABYTE:
            fs.bpb.BPB_SecPerClus = 4096 // mbr.SECTOR_SIZE
        elif 8 * GIGABYTE <= size < 16 * GIGABYTE:
            fs.bpb.BPB_SecPerClus = 8192 // mbr.SECTOR_SIZE
        elif 16 * GIGABYTE <= size < 32 * GIGABYTE:
            fs.bpb.BPB_SecPerClus = 16384 // mbr.SECTOR_SIZE
        else:
            raise RuntimeError("file system size greater than 2TB not supported")

        fs.bpb.BPB_RsvdSecCnt = 32  # from Linux example
        fs.bpb.BPB_NumFATs = 2
        fs.bpb.BPB_RootEntCnt = 0

        total_sector_count = size // mbr.SECTOR_SIZE
        if total_sector_count < 0xFFFF:
            fs.bpb.BPB_TotSec16 = total_sector_count
            fs.bpb.BPB_TotSec32 = 0
        else:
            fs.bpb.BPB_TotSec16 = 0
            fs.bpb.BPB_TotSec32 = total_sector_count

        fs.bpb.BPB_Media = 248  # from Linux example
        fs.bpb.BPB_FATSz16 = 0
        # for CHS, can use zero, and for LBA mode
        # via: https://en.wikipedia.org/wiki/Master_boot_record
        fs.bpb.BPB_SecPerTrk = 0
        fs.bpb.BPB_NumHeads = 0
        fs.bpb.BPB_HiddSec = 0

        total_cluster_count = total_sector_count // fs.bpb.BPB_SecPerClus
        fs.bpb.BPB_FATSz32 = (4 * total_cluster_count) // mbr.SECTOR_SIZE

        fs.bpb.BPB_ExtFlags = 0
        fs.bpb.BPB_FSVer = 0
        fs.bpb.BPB_RootClus = 2
        fs.bpb.BPB_FSInfo = 1
        fs.bpb.BPB_BkBootSec = 6
        fs.bpb.BPB_DrvNum = 128  # from Linux example
        fs.bpb.BPB_Reserved1 = 0
        fs.bpb.BPB_BootSig = 41
        fs.bpb.BPB_VolID = 4107516940  # from Linux example
        fs.bpb.BPB_VolLab = b"NO NAME    "
        fs.bpb.BPB_FilSysType = b"FAT32   "
        fs.bpb.BPB_BootCode = NOBOOT_CODE
        fs.bpb.EndOfSectorMarker = 0xAA55


    # the the FS is first parsed, it may not create structures for the
    # backup BPB, FS info, or FATs, since they're not referenced in a NULL primary BPB.
    # so, we reload the FS using the initial BPB set just above.
    with open(path, "r+b") as f:
        fs.vsLoad(f, partition_offset, writeback=True)

        fs.bpb_backup.BPB_jmpBoot = fs.bpb.BPB_jmpBoot
        fs.bpb_backup.BPB_OEMName = fs.bpb.BPB_OEMName
        fs.bpb_backup.BPB_BytsPerSec = fs.bpb.BPB_BytsPerSec
        fs.bpb_backup.BPB_SecPerClus = fs.bpb.BPB_SecPerClus
        fs.bpb_backup.BPB_RsvdSecCnt = fs.bpb.BPB_RsvdSecCnt
        fs.bpb_backup.BPB_NumFATs = fs.bpb.BPB_NumFATs
        fs.bpb_backup.BPB_RootEntCnt = fs.bpb.BPB_RootEntCnt
        fs.bpb_backup.BPB_TotSec16 = fs.bpb.BPB_TotSec16
        fs.bpb_backup.BPB_TotSec32 = fs.bpb.BPB_TotSec32
        fs.bpb_backup.BPB_Media = fs.bpb.BPB_Media
        fs.bpb_backup.BPB_FATSz16 = fs.bpb.BPB_FATSz16
        fs.bpb_backup.BPB_SecPerTrk = fs.bpb.BPB_SecPerTrk
        fs.bpb_backup.BPB_NumHeads = fs.bpb.BPB_NumHeads
        fs.bpb_backup.BPB_HiddSec = fs.bpb.BPB_HiddSec
        fs.bpb_backup.BPB_FATSz32 = fs.bpb.BPB_FATSz32
        fs.bpb_backup.BPB_ExtFlags = fs.bpb.BPB_ExtFlags
        fs.bpb_backup.BPB_FSVer = fs.bpb.BPB_FSVer
        fs.bpb_backup.BPB_RootClus = fs.bpb.BPB_RootClus
        fs.bpb_backup.BPB_FSInfo = fs.bpb.BPB_FSInfo
        fs.bpb_backup.BPB_BkBootSec = fs.bpb.BPB_BkBootSec
        fs.bpb_backup.BPB_DrvNum = fs.bpb.BPB_DrvNum
        fs.bpb_backup.BPB_Reserved1 = fs.bpb.BPB_Reserved1
        fs.bpb_backup.BPB_BootSig = fs.bpb.BPB_BootSig
        fs.bpb_backup.BPB_VolID = fs.bpb.BPB_VolID
        fs.bpb_backup.BPB_VolLab = fs.bpb.BPB_VolLab
        fs.bpb_backup.BPB_FilSysType = fs.bpb.BPB_FilSysType
        fs.bpb_backup.BPB_BootCode = fs.bpb.BPB_BootCode
        fs.bpb_backup.EndOfSectorMarker = fs.bpb.EndOfSectorMarker

        for f in fs.fats:
            f[0] = 0x0FFFFFF8  # from Linux sample
            f[1] = 0x0FFFFFFF

            # set root dir cluster chain
            f[2] = fat32.CLUSTER_TYPES.LAST

        fs.fs_info.FSI_LeadSig = 0x41615252
        fs.fs_info.FSI_StrucSig = 0x61417272
        fs.fs_info.FSI_TailSig = 0xAA550000


@contextlib.contextmanager
def test_image():
    try:
        os.remove(TEST_IMAGE_PATH)
    except:
        pass

    with open(TEST_IMAGE_PATH, "wb") as f:
        f.write(b"\x00" * TEST_IMAGE_SIZE)

    try:
        yield

    finally:
        #os.remove(TEST_IMAGE_PATH)
        pass


@contextlib.contextmanager
def test_fs():
    with test_image():
        set_first_partition_fat32(TEST_IMAGE_PATH, TEST_PART_SIZE)
        with mbr.MBR(TEST_IMAGE_PATH) as m:
            partition_offset = m.Partitions[0].RelativeSector * mbr.SECTOR_SIZE

        create_fat32_filesystem(TEST_IMAGE_PATH, partition_offset, TEST_PART_SIZE)

        fs = fat32.FAT32(False)
        with open(TEST_IMAGE_PATH, "r+b") as f:
            fs.vsLoad(f, partition_offset, writeback=True)
            yield fs


@contextlib.contextmanager
def test_logical_fs():
    with test_fs() as fs:
        yield fat32.FAT32LogicalFileSystem(fs)


class TestPyFAT(unittest.TestCase):
    def test_make_partition(self):
        with test_image():
            set_first_partition_fat32(TEST_IMAGE_PATH, TEST_PART_SIZE)

            with mbr.MBR(TEST_IMAGE_PATH) as m:
                self.assertEqual(m.Partitions[0].SystemID, mbr.SYSTEMID.PRI_FAT32_INT13)
                self.assertEqual(m.Partitions[0].RelativeSector, 2048)
                self.assertEqual(m.Partitions[0].TotalSectors, TEST_PART_SIZE // mbr.SECTOR_SIZE)

    def test_make_filesystem(self):
        with test_image():
            set_first_partition_fat32(TEST_IMAGE_PATH, TEST_PART_SIZE)

            with test_fs() as fs:
                self.assertEqual(fs.bpb.BPB_NumFATs, 2)
                self.assertEqual(fs.bpb_backup.BPB_NumFATs, 2)

    def test_cluster_access(self):
        with test_fs() as fs:
            # test directly set cluster content
            self.assertEqual(len(fs.clusters[3]), fs.cluster_size)
            self.assertEqual(bytes(fs.clusters[3]), b"\x00" * fs.cluster_size)
            fs.clusters[3] = b"\x69" * fs.cluster_size
            self.assertEqual(bytes(fs.clusters[3]), b"\x69" * fs.cluster_size)

            # although the data is set, the cluster is still free
            # FAT table: [0] reserved, [1] reserved, [2] root, [3] free, [4] free
            self.assertEqual(fs.isClusterFree(3), True)
            # since nothing's been allocated, clusters 0 and 1 are reserved, root entry is 2,
            # so the first free cluster is 3
            self.assertEqual(fs.getFreeClusterNumber(), 3)

            # FAT table: [0] reserved, [1] reserved, [2] root, [3] LAST, [4] free
            fs.markClusterUsed(3)
            self.assertEqual(fs.isClusterFree(3), False)
            self.assertEqual(fs.getFreeClusterNumber(), 4)
            self.assertEqual(fs.getClusterChain(3), [3, fat32.CLUSTER_TYPES.LAST])

            # FAT table: [0] reserved, [1] reserved, [2] root, [3] free, [4] free
            fs.markClusterFree(3)
            self.assertEqual(fs.isClusterFree(3), True)

            # FAT table: [0] reserved, [1] reserved, [2] root, [3] 4, [4] LAST
            fs.markClusterUsed(4)
            fs.markClusterUsed(3, 4)
            self.assertEqual(fs.getClusterChain(3), [3, 4, fat32.CLUSTER_TYPES.LAST])
            fs.markClusterFree(3)
            fs.markClusterFree(4)

            # test small run
            with self.assertRaises(fat32.FileDoesNotExistException):
                fs.getContent(3)

            p = fs.addContent(b"hello world!")
            self.assertEqual(fs.getContent(p).rstrip(b"\x00"), b"hello world!")
            fs.delContent(p)

            with self.assertRaises(fat32.FileDoesNotExistException):
                fs.getContent(p)

            # test empty run
            with self.assertRaises(fat32.FileDoesNotExistException):
                fs.getContent(3)

            p = fs.addContent(b"")
            self.assertEqual(fs.getContent(p).rstrip(b"\x00"), b"")
            fs.delContent(p)

            with self.assertRaises(fat32.FileDoesNotExistException):
                fs.getContent(p)

            # test writing and overwriting data runs with smaller, equal, and bigger data
            cases = [
                        {"cluster_count_one": 0, "cluster_count_two": 0},
                        {"cluster_count_one": 0, "cluster_count_two": 1},
                        {"cluster_count_one": 0, "cluster_count_two": 2},

                        {"cluster_count_one": 1, "cluster_count_two": 0},
                        {"cluster_count_one": 1, "cluster_count_two": 1},
                        {"cluster_count_one": 1, "cluster_count_two": 2},

                        {"cluster_count_one": 2, "cluster_count_two": 0},
                        {"cluster_count_one": 2, "cluster_count_two": 1},
                        {"cluster_count_one": 2, "cluster_count_two": 2}
                    ]

            for case in cases:
                v1 = b"A" * fs.cluster_size * case["cluster_count_one"]
                v2 = b"B" * fs.cluster_size * case["cluster_count_two"]

                p = fs.addContent(v1)
                self.assertEqual(fs.getContent(p).rstrip(b"\x00"), v1)

                fs.setContent(p, v2)
                self.assertEqual(fs.getContent(p).rstrip(b"\x00"), v2)

                fs.delContent(p)

    def test_directories83(self):
        with test_logical_fs() as fs:
            self.assertEqual(list(fs.listFiles()), [])
            self.assertEqual(list(fs.listDirectories()), [])
            with self.assertRaises(fat32.FileDoesNotExistException):
                fs.readFile("/DNE.TXT")

            with self.assertRaises(fat32.FileDoesNotExistException):
                fs.delDirectory("/TEST")

            fs.addDirectory("/TEST")
            self.assertEqual(list(fs.listDirectories()), ["/TEST"])

            with self.assertRaises(fat32.FileExistsException):
                fs.addDirectory("/TEST")

            fs.delDirectory("/TEST")
            self.assertEqual(list(fs.listDirectories()), [])

    def test_files83(self):
        with test_logical_fs() as fs:
            self.assertEqual(list(fs.listFiles()), [])
            self.assertEqual(list(fs.listDirectories()), [])
            with self.assertRaises(fat32.FileDoesNotExistException):
                fs.readFile("/DNE.TXT")

            with self.assertRaises(fat32.FileDoesNotExistException):
                fs.delFile("/TEST.TXT")

            fs.addFile("/TEST.TXT", b"AA")
            self.assertEqual(list(fs.listFiles()), ["/TEST.TXT"])
            self.assertEqual(fs.readFile("/TEST.TXT"), b"AA")

            with self.assertRaises(fat32.FileExistsException):
                fs.addFile("/TEST.TXT", b"BB")

            fs.delFile("/TEST.TXT")
            self.assertEqual(list(fs.listFiles()), [])

            # can't simply list directories, since we support long names
            # so need to access the files by short name directly
            fs.addFile("/TEST-LONG.TXT", b"AA")
            self.assertEqual(fs.readFile("/TEST-L~0.TXT"), b"AA")
            fs.addFile("/TEST-LONG1.TXT", b"BB")
            self.assertEqual(fs.readFile("/TEST-L~1.TXT"), b"BB")

    def test_directories(self):
        with test_logical_fs() as fs:
            self.assertEqual(list(fs.listFiles()), [])
            self.assertEqual(list(fs.listDirectories()), [])
            with self.assertRaises(fat32.FileDoesNotExistException):
                fs.readFile("/dne.txt")

            with self.assertRaises(fat32.FileDoesNotExistException):
                fs.delDirectory("/test-longlong")

            # this value extracted from an entry created by the Windows FAT32 driver
            self.assertEqual(fat32.DIRECTORY_DATA.compute83Hash("TEST-L~1   "), 0x7)

            fs.addDirectory("/test-longlonglonglong")
            self.assertEqual(list(fs.listDirectories()), ["/test-longlonglonglong"])

            with self.assertRaises(fat32.FileExistsException):
                fs.addDirectory("/test-longlonglonglong")

            fs.addDirectory("/test-longlonglonglong/hahahahahahahahahaha")
            self.assertEqual(list(fs.listDirectories()), ["/test-longlonglonglong", "/test-longlonglonglong/hahahahahahahahahaha"])

            with self.assertRaises(fat32.DirectoryNotEmptyException):
                fs.delDirectory("/test-longlonglonglong")

            fs.delDirectory("/test-longlonglonglong/hahahahahahahahahaha")
            self.assertEqual(list(fs.listDirectories()), ["/test-longlonglonglong"])

            fs.delDirectory("/test-longlonglonglong")
            self.assertEqual(list(fs.listDirectories()), [])

    def test_files(self):
        with test_logical_fs() as fs:
            self.assertEqual(list(fs.listFiles()), [])
            self.assertEqual(list(fs.listDirectories()), [])
            with self.assertRaises(fat32.FileDoesNotExistException):
                fs.readFile("/dne.txt")

            with self.assertRaises(fat32.FileDoesNotExistException):
                fs.delFile("/test-longlong.txt")

            fs.addFile("/test-longlong.txt", b"AA")
            self.assertEqual(list(fs.listFiles()), ["/test-longlong.txt"])
            self.assertEqual(fs.readFile("/test-longlong.txt"), b"AA")

            with self.assertRaises(fat32.FileExistsException):
                fs.addFile("/test-longlong.txt", b"AA")

            fs.delFile("/test-longlong.txt")
            self.assertEqual(list(fs.listFiles()), [])

            fs.addDirectory("/test-longlonglonglong")
            self.assertEqual(list(fs.listDirectories()), ["/test-longlonglonglong"])

            fs.addFile("/test-longlonglonglong/test-longlong.txt", b"AA")
            self.assertEqual(list(fs.listFiles()), ["/test-longlonglonglong/test-longlong.txt"])
            self.assertEqual(fs.readFile("/test-longlonglonglong/test-longlong.txt"), b"AA")

            with self.assertRaises(fat32.DirectoryNotEmptyException):
                fs.delDirectory("/test-longlonglonglong")
            self.assertEqual(list(fs.listFiles()), ["/test-longlonglonglong/test-longlong.txt"])

            fs.delFile("/test-longlonglonglong/test-longlong.txt")
            self.assertEqual(list(fs.listFiles()), [])
            fs.delDirectory("/test-longlonglonglong")


def test():
    logging.basicConfig(level=logging.DEBUG)
    try:
        unittest.main()
    except SystemExit:
        pass


if __name__ == '__main__':
    test()

