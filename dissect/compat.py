'''
Isolate 2.7 compatibility filth.
'''
import sys

major = sys.version_info.major
minor = sys.version_info.minor
micro = sys.version_info.micro

version = (major,minor,micro)

if version <= (3,0,0):

    def iterbytes(byts):
        for c in byts:
            yield ord(c)

else:

    def iterbytes(byts):
        return iter(byts)

