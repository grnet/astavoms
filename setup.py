#!/usr/bin/env python

# Copyright 2015-2016 GRNET S.A.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from setuptools import setup
from astavoms import __version__

setup(
    name='astavoms',
    version=__version__,
    description=('a minimal proxy server able to translate VOMS user '
                 'information to Synnefo/Astakos credentials, with tools.'),
    long_description=open('README.md').read(),
    url='',
    download_url='',
    license='BSD',
    author='Stavros Sachtouris',
    author_email='saxtouri@admin.grnet.gr',
    maintainer='Stavros Sachtouris',
    maintainer_email='saxtouri@admin.grnet.gr',
    packages=['astavoms', 'astavoms.authvoms'],
    classifiers=[
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Environment :: Console',
        'License :: OSI Approved :: BSD License',
        'Natural Language :: English',
        'Topic :: System :: Shells',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Utilities'
        ],
    include_package_data=True,
    entry_points={
        'console_scripts': [
            'astavoms-server = astavoms.daemon:cli',
            'astavoms-pool = astavoms.userpool:cli',
        ]
    },
    install_requires=[
        'kamaki', 'python-ldap', 'Flask', 'M2Crypto', 'psycopg2',
    ]
)
