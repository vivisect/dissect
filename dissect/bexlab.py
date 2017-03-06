'''
A special FileLab extension to facilitate parsing and
normalization of binary executable constructs.
'''

from dissect.common import KeyCache
from dissect.filelab import FileLab


class BexLab(FileLab):
    '''
    bex:arch = <name>       - A unified standard for arch names
    bex:ptr:size = <size>   - Pointer width in bytes
    bex:ptr:base = <addr>   - Base/Load address for the image

    - Memory maps
    bex:mem:maps = [ (rva,info), ... ]

    #bex:relocs = [ (rva,info), ... ]
    #bex:imports = [ (rva,info), ... ]
    #bex:exports = [ (rva,info), ... ]
    '''
    def __init__(self, fd, off=0):
        FileLab.__init__(self, fd, off=off)
        self._bex_rva2off = KeyCache( self._rvaToOff )

    def rvaToOff(self, rva):
        '''
        Translate a relative virtual address to a file offset.
        '''
        return self._bex_rva2off[rva]

    def _rvaToOff(self, rva):

        # use the genericized bex memory maps
        for memrva,meminfo in self.get('bex:mem:maps'):

            off = meminfo.get('off')
            # if off is none, it's not in the file byts
            if off == None:
                continue

            size = meminfo.get('size')
            memmax = memrva + size
            if rva >= memrva and rva < memmax:
                return off + (rva - memrva)
