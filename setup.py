#!/usr/bin/env python
#from distutils.core import setup
from setuptools import setup,find_packages

# For Testing:
#
# python3.4 setup.py register -r https://testpypi.python.org/pypi
# python3.4 setup.py bdist_wheel upload -r https://testpypi.python.org/pypi
# python3.4 -m pip install -i https://testpypi.python.org/pypi
#
# For Realz:
#
# python3.4 setup.py register
# python3.4 setup.py bdist_wheel upload
# python3.4 -m pip install

import dissect

setup(
    name='dissect',
    version='.'.join( str(v) for v in dissect.__version__ ),
    description='Vivisect (Mark II) File/Protocol Parsers',
    author='Invisigoth Kenshoto',
    author_email='visi@vertex.link',
    url='https://github.com/vivisect/dissect',
    license='Apache License 2.0',

    packages=find_packages(exclude=['*.tests','*.tests.*']),

    install_requires=[
        'vstruct2>=2.0.2',
    ],

    classifiers=[
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3.4',
    ],

)
