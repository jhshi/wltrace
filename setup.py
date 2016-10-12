try:
    from setuptools import setup, find_packages
except ImportError:
    from distutils.core import setup, find_packages

import sys
import platform
import os

from wltrace import __version__

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

install_requires = [
    'python-dateutil>=2.5.3',
    'progressbar>=2.3',
]

if platform.python_implementation() == 'CPython':
    install_requires.append('numpy>=1.10')
elif platform.python_implementation() == 'PyPy':
    install_requires.append('numpy-pypy>=1.9')

setup(
    name='wltrace',
    version=__version__,
    description="A Python library to parse Pcap (w/ Radtiotap) and Peektagged packet traces.",

    author='Jinghao Shi',
    author_email='jhshi89@gmail.com',

    url='https://github.com/jhshi/wltrace',
    download_url='https://github.com/jhshi/wltrace/tarball/%s' % (__version__),

    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 2.7',
        'Topic :: System :: Networking :: Monitoring',
    ],
    keywords=['pcap', 'radiotap', 'peektagged', 'trace'],

    packages=find_packages(),

    install_requires=install_requires,
    include_package_data=True,
)
