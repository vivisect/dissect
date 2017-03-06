import collections

class KeyCache(collections.defaultdict):
    '''
    A dictionary based key/val cache.

    Example:

        cache = KeyCache( getFooThing )

        if cache['woot']:
            dostuff()

    '''
    def __init__(self, lookmeth):
        collections.defaultdict.__init__(self)
        self.lookmeth = lookmeth

    def __missing__(self, key):
        valu = self.lookmeth(key)
        self[key] = valu
        return valu

class OnDemand(collections.defaultdict):

    def __init__(self):
        collections.defaultdict.__init__(self)
        self._ondem_ctors = {}

    def add(self, name, ctor, *args, **kwargs):
        '''
        Add on-demand parser callback.

        Example:

            class FooLab(FileLab):

                def __init__(self, fd, off=0):
                    FileLab.__init__(self, fd, off=off)
                    self.add('bars', self._getFooBars )

                def _getFooBars(self):
                    return []

            foo = FooLab()
            for bar in foo.get('bars'):
                dostuff()
        '''
        self._ondem_ctors[name] = (ctor,args,kwargs)

    def get(self, name, defval=None):
        '''
        Retrieve the results of an on-demand parser callback.

        Example:

            for bar in foo.get('bars'):
                dostuff()

        '''
        retn = self[name]
        if retn == None:
            retn = defval
        return retn

    def set(self, name, valu):
        '''
        Set an explicit value in the on-demand dict.
        '''
        self[name] = valu

    def __missing__(self, key):
        meth,args,kwargs = self._ondem_ctors.get(key)
        val = meth(*args,**kwargs)
        self[key] = val
        return val

def colify(rows,titles=None):
    '''
    Generate colum text output from rows.

    Example:

        rows = [
            ('bob','33'),
            ('bill','24')
        ]

        print( colify( rows, titles=('name','age') ))

    '''
    colcount = max([ len(r) for r in rows ])

    colsizes = collections.defaultdict(int)
    if titles != None:
        for i in range(len(titles)):
            colsizes[i] = len(titles[i])

    for i in range(colcount):
        for j in range(len(rows)):
            colsizes[i] = max(colsizes[i], len(rows[j][i]))

    sumlen = sum( colsizes.values() ) + ( 3 * colcount )

    lines = []
    lines.append( '-' * sumlen )
    if titles:
        pres = [ titles[i].ljust(colsizes[i]) for i in range(colcount) ]
        lines.append(' | '.join(pres))
        lines.append('-' * sumlen)

    for row in rows:
        pres = [ row[i].ljust(colsizes[i]) for i in range(colcount) ]
        lines.append( ' | '.join(pres) )
    lines.append( '-' * sumlen )

    return '\n'.join(lines)
