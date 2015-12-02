import unittest

import dissect.formats.rar as rar
import dissect.tests.files as files

class RarTest(unittest.TestCase):

    #def test_rar_iv(self):

    def test_rar_filelab(self):

        fd = files.getTestFd('test.rar')
        lab = rar.RarLab(fd)

        #print(rarlab['header'])
        #rarlab['header'].vsPrint()

        #self.assertEqual( len(list(lab.iterRar4Files())), 4 )

        #for hdr in rarlab.iterRar4Files():
            #hdr.vsPrint()

