import io
import unittest

from vstruct2.types import *
from dissect.filelab import *

class CommonTest(unittest.TestCase):

    def test_filelab(self):

        fd = io.BytesIO( b'asdfqwer' )

        class Woot(VStruct):
            def __init__(self):
                VStruct.__init__(self)
                self.one = uint8()
                self.two = uint16()

        class FooLab(FileLab):
            def __init__(self, fd, off=0):
                FileLab.__init__(self, fd, off=off)

                self.add('woot',self._getWoot)
                self.add('baz',self._getFooBaz)
                self.add('bars',self._getFooBars)

            def _getFooBaz(self):
                return 'foobaz'

            def _getFooBars(self):
                return ('foo','bar','baz')

            def _getWoot(self):
                return self.getStruct( 0, Woot )

        foo = FooLab(fd)
        self.assertEqual( foo['baz'], 'foobaz' )
        self.assertEqual( foo['bars'], ('foo','bar','baz') )

        self.assertEqual( foo['woot'].one, 0x61 )

