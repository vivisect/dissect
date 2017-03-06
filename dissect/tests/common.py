import unittest

class DisTest(unittest.TestCase):

    def eq(self, x, y):
        self.assertEqual(x,y)

    def ne(self, x, y):
        self.assertNotEqual(x,y)

    def nn(self, x):
        self.assertIsNotNone(x)

    def true(self, x):
        self.assertTrue(x)

    def false(self, x):
        self.assertFalse(x)
