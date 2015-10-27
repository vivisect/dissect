import sys
import argparse

import dissect.formats.cab as d_cab

from dissect.common import *

def main(argv):

    p = argparse.ArgumentParser()
    p.add_argument('--list',default=False, action='store_true', help='list files within the cab file')
    p.add_argument('--catfile',help='cat a file from cab to stdout')
    p.add_argument('cabfiles',nargs='+',help='ms cab files')

    args = p.parse_args(argv)

    for filename in args.cabfiles:
        fd = open(filename,'rb')

        cab = d_cab.CabLab(fd)
        if args.list:
            ver = cab.getCabVersion()
            size = cab.getCabSize()
            verstr = '.'.join([ str(v) for v in ver ])
            print('listing cab: %s (ver: %s)' % (filename,verstr))

            rows = []
            for name,info in cab.listCabFiles():
                rows.append( (name, str(info['size']), info['comp']) )

            titles = ('File Name','Size','Compression')
            print( colify( rows, titles=titles) )
            continue

        if args.catfile:
            cab['CFHEADER'].vsPrint()
            fd = cab.openCabFile( args.catfile )
            fd.seek(0)
            print(repr(fd.read()))
            

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

