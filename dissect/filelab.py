import codecs

from dissect.common import *

class FileLab(OnDemand):
    '''
    Base class for file format parsers.

    The FileLab class provides routines to help file parsers
    with concepts like API caching and on-demand parsing.

    Example:

        class FooLab(FileLab):

            def __init__(self, fd, off=0):
                FileLab.__init__(self, fd, off=off)

                self.add('foo', self._getFoo )
                self.add('bars', self._getFooBars )

            def _getFoo(self):
                return 'foo'

            def _getFooBars(self):
                return ['bar','bar','bar']

        foo = FooLab()

        for bar in foo.get('bars'):
            dostuff()

    '''
    def __init__(self, fd, off=0):
        OnDemand.__init__(self)
        self.fd = fd
        self.off = off

    def getStruct(self, off, cls, *args, **kwargs):
        '''
        Construct a VStruct and load from the file offset.

        Example:

            class Foo(VStruct):
                # ...

            foo = lab.getStruct(0, Foo)

        Notes:

            * if off is unspecified, the current file offset is used

        '''
        if off == None:
            off = self.fd.tell()

        obj = cls(*args,**kwargs)
        obj.vsLoad( self.fd, offset=off )
        return obj

    def readAtOff(self, off, size, shortok=False):
        self.fd.seek(off)
        byts = self.fd.read(size)
        if len(byts) != size and not shortok:
            raise Exception('readAtOff(%d,%d) short: %d' % (off,size,len(byts)))
        return byts

    def strAtOff(self, off, codec='utf8'):
        '''
        Incrementally decode and return a null terminated string.
        '''
        self.fd.seek(off)
        def fdbytes():
            while True:
                b = self.fd.read(1)
                if not b:
                    break
                yield b

        ret = []
        for c in codecs.iterdecode(fdbytes(),codec):
            if ord(c) == 0:
                break

            ret.append(c)

        return ''.join(ret)
