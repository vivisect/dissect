import hashlib
import unittest

import dissect.formats.cab as cab
import dissect.tests.files as files

class CabTest(unittest.TestCase):
    hash_chk = '00010548964e7bbca74da0d1764bdd70'

    def test_cab_decomp(self):
        with files.getTestFd('test_cab.cab') as fd:

            c = cab.CabLab(fd)
            for fname,finfo,cab_fd in c.getCabFiles():
                self.assertEqual(fname, 'test_cab.txt')
                dec_data = cab_fd.read()
                
                h = hashlib.md5()
                h.update(dec_data)
                
                self.assertEqual(self.hash_chk, h.hexdigest())
