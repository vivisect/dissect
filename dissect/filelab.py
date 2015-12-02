
from dissect.common import *

class FileLab:
    '''
    Base class for file format parsers.

    The FileLab class provides routines to help file parsers
    with concepts like API caching and on-demand parsing.

    Example:

        class FooLab(FileLab):

            def __init__(self, fd, off=0):
                FileLab.__init__(self, fd, off=off)

                self.addOnDemand('foo', self._getFoo )
                self.addOnDemand('bars', self._getFooBars )

                self.barbybaz = LookDict( self._getBarByBaz )

            def getBarByBaz(self, baz):
                return self.barbybaz[baz]

            def _getBarByBaz(self, baz):
                return dostuff(baz)

            def _getFoo(self):
                return 'foo'

            def _getFooBars(self):
                return ['bar','bar','bar']

        foo = FooLab()

        for bar in foo['bars']:
            dostuff()

    '''
    def __init__(self, fd, off=0):
        self.fd = fd
        self.off = off
        self.ondem = OnDemand()

        #self.addOnDemand('md5', self._onDemMd5 )
        #self.addOnDemand('sha1', self._onDemSha1 )
        #self.addOnDemand('sha256', self._onDemSha256 )

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

    def addOnDemand(self, name, meth):
        '''
        Add on-demand parser callback.

        Example:

            class FooLab(FileLab):

                def __init__(self, fd, off=0):
                    FileLab.__init__(self, fd, off=off)
                    self.addOnDemand('bars', self._getFooBars )

                def _getFooBars(self):
                    return []

            foo = FooLab()
            for bar in foo['bars']:
                dostuff()

        '''
        self.ondem.add(name,meth)

    def getOnDemand(self, name):
        '''
        Retrieve the results of an on-demand parser callback.

        Example:

            for bar in foo.getOnDemand('bars'):
                dostuff()

        '''
        return self.ondem[name]

    def __getitem__(self, name):
        return self.ondem[name]

