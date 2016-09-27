try:
    from setuptools import setup, find_packages
except ImportError:
    from distutils.core import setup, find_packages

import sys
import os
from setuptools.command.test import test as TestCommand

from wltrace.version import __version__

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

with open('requirements.txt', 'r') as f:
    requirements = f.read().splitlines()


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
        #import here, cause outside the eggs aren't loaded
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

    author='Jinghao Shi',
    author_email='jinghaos@buffalo.edu',

    url='',

    classifiers=[
      'Development Status :: 3 - Alpha',
      'Intended Audience :: Developers',

      'Programming Language :: Python :: 2',
      'Programming Language :: Python :: 2.7',
      ],

    packages=find_packages(),

    install_requires=requirements,

    tests_require=['tox'],
    cmdclass = {'test': Tox},
    include_package_data=True,
    )
