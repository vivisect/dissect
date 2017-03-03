import os
filesdir = os.path.dirname( __file__ )

def getTestFd(*names):
    path = os.path.join(filesdir,*names)
    return open(path,'rb')

