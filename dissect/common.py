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
        self.ctors = {}
        self.names = []

    def add(self, name, ctor, *args, **kwargs):
        self.names.append(name)
        self.ctors[name] = (ctor,args,kwargs)

    def __missing__(self, key):
        meth,args,kwargs = self.ctors.get(key)
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
