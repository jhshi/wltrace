try:
    from setuptools import setup, find_packages
except ImportError:
    from distutils.core import setup, find_packages

import sys
import platform
import os
from setuptools.command.test import test as TestCommand

from wltrace import __version__

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

with open('common-requirements.txt', 'r') as f:
    requirements = f.read().splitlines()

if 'PyPy' not in platform.python_implementation():
    with open('py27-requirements.txt', 'r') as f:
        requirements.append(f.read().splitlines()[0])


class Tox(TestCommand):
    user_options = [('tox-args=', 'a', "Arguments to pass to tox")]

    def initialize_options(self):
        TestCommand.initialize_options(self)
        self.tox_args = None

    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        # import here, cause outside the eggs aren't loaded
        import tox
        import shlex
        args = self.tox_args
        if args:
            args = shlex.split(self.tox_args)
        errno = tox.cmdline(args=args)
        sys.exit(errno)


setup(
    name='wltrace',
    version=__version__,
    description="A library to parse wireless packet traces.",

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
    keywords=['pcap', 'peektagged', 'trace'],

    packages=find_packages(),

    install_requires=requirements,

    tests_require=['tox'],
    cmdclass={'test': Tox},
    include_package_data=True,
)
