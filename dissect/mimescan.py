

typers = []
scanners = []

def scanForMimes(fd, off=0, only=None, ignore=None):
    '''
    Scan an fd for "carveable" files.
    Returns (offset,mimetype) tuples.

    Example:

        for off,mime in scanForMimes(fd):
            carvestuff(fd,off)

    '''
    for mime,scanner in scanners:

        if only != None and mime not in only:
            continue

        if ignore != None and mime in ignore:
            continue

        fd.seek(off)

        for hit in scanner(fd):
            yield (mime,hit)

def getMimeType(fd):
    '''
    Returns a mime type name for the file content.
    '''
