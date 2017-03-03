import unittest

from dissect.common import *

class CommonTest(unittest.TestCase):

    def test_common_ondemand(self):
        def foo():
            return 'foo'

        def bar(x):
            return x + 20

        def baz(x,y=0):
            return x + y

        ondem = OnDemand()
        ondem.add('foo',foo)
        ondem.add('bar',bar, 10)
        ondem.add('baz',baz, 10, y=40)

        self.assertEqual( ondem['foo'], 'foo' )

        self.assertEqual( ondem['bar'], 30 )
        self.assertEqual( ondem['baz'], 50 )

    def test_common_keycache(self):
        data = {'hits':0}
        def woot(x):
            data['hits'] += 1
            return x + 20

        cache = KeyCache(woot)

        self.assertEqual( cache[10], 30 )
        self.assertEqual( cache[10], 30 )
        self.assertEqual( cache[10], 30 )

        self.assertEqual( data['hits'], 1 )

        self.assertEqual( cache[20], 40 )
        self.assertEqual( data['hits'], 2 )
