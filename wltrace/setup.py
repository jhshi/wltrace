try:
  from setuptools import setup, find_packages
except ImportError:
  from distutils.core import setup, find_packages

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

with open('production-requirements.txt', 'r') as f:
  requirements = f.read().splitlines()

setup(
    name='pyparser',
    version=__version__,

    author='Jinghao Shi',
    author_email='v-jinghs@microsoft.com',

    url='tbd',

    classifiers=[
      'Development Status :: 3 - Alpha',
      'Intended Audience :: Developers',

      'Programming Language :: Python :: 2',
      'Programming Language :: Python :: 2.7',
      ],

    packages=find_packages(),

    entry_points={
      'console_scripts': ['pyparser = pyparser.main:main']
      },

    install_requires=requirements,

    include_package_data=True,
    package_data= {
      },
    )
