import unittest

import dissect.formats.pe as d_pe
import dissect.tests.files as d_files

from dissect.tests.common import DisTest

class CabTest(DisTest):

    def test_pe_putty32(self):
        with d_files.getTestFd('putty32.exe') as fd:

            self.true( d_pe.isMimePe(fd) )

            fd.seek(0)

            lab = d_pe.PeLab(fd)

            self.eq( lab.get('pe:dllname'), None )

            #lab.get('pe:IMAGE_DOS_HEADER').vsPrint()
            #lab.get('pe:IMAGE_NT_HEADERS').vsPrint()

            #lab.get('pe:sections').vsPrint()

            self.eq( lab.get('bex:arch'), 'i386')
            self.eq( lab.get('bex:ptr:size'), 4 )

            self.eq( lab.rvaToOff(0x10), 0x10 )
            self.eq( lab.rvaToOff(0x7c010), 503312 )

            self.nn( lab.getSectByName('.reloc') )

    def test_pe_putty64(self):

        with d_files.getTestFd('putty64.exe') as fd:

            self.true( d_pe.isMimePe(fd) )

            fd.seek(0)

            lab = d_pe.PeLab(fd)

            self.eq( lab.get('pe:dllname'), None )

            #lab.get('pe:IMAGE_DOS_HEADER').vsPrint()
            #lab.get('pe:IMAGE_NT_HEADERS').vsPrint()

            self.eq( lab.get('bex:arch'), 'amd64')
            self.eq( lab.get('bex:ptr:size'), 8 )

            #lab.get('pe:sections').vsPrint()

            self.eq( lab.rvaToOff(0x10), 0x10 )
            self.eq( lab.rvaToOff(0x7c010), 504848 )

            self.nn( lab.getSectByName('.reloc') )

    def test_pe_hello32(self):

        with d_files.getTestFd('hello32.dll') as fd:

            self.true( d_pe.isMimePe(fd) )

            fd.seek(0)

            lab = d_pe.PeLab(fd)

            self.eq( lab.get('pe:dllname'), 'hellodll_i386.dll' )

            self.eq( lab.get('bex:arch'), 'i386')
            self.eq( lab.get('bex:ptr:size'), 4 )

    def test_pe_hello64(self):

        with d_files.getTestFd('hello64.dll') as fd:

            self.true( d_pe.isMimePe(fd) )

            fd.seek(0)

            lab = d_pe.PeLab(fd)

            self.eq( lab.get('pe:dllname'), 'hellodll_amd64.dll' )

            self.eq( lab.get('bex:arch'), 'amd64')
            self.eq( lab.get('bex:ptr:size'), 8 )

