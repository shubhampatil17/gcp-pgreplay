from __future__ import print_function
from setuptools import setup, find_packages
from setuptools.command.test import test as TestCommand

import io
import os
import sys
import gcppgreplay

here = os.path.abspath(os.path.dirname(__file__))


def read(*filenames, **kwargs):
    encoding = kwargs.get('encoding', 'utf-8')
    sep = kwargs.get('sep', '\n')
    buf = []
    for filename in filenames:
        with io.open(filename, encoding=encoding) as f:
            buf.append(f.read())
    return sep.join(buf)


long_description = read('README.txt', 'CHANGES.txt')


class PyTest(TestCommand):
    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        import pytest
        errcode = pytest.main(self.test_args)
        sys.exit(errcode)


setup(
    name='gcppgreplay',
    version=gcppgreplay.__version__,
    url='https://github.com/shubhampatil17/gcp-pgreplay/',
    license='Apache Software License',
    author='Shubham Patil',
    tests_require=[
        'pytest'
    ],
    install_requires=[
        'argparse',
        'google-auth-oauthlib',
        'google-cloud-logging',
        'pgsanity'
    ],
    cmdclass={'test': PyTest},
    author_email='patil.sm17@gmail.com',
    description='A disaster recovery command line utility to fetch Google Cloud SQL (Postgres) transaction logs',
    long_description=long_description,
    packages=['gcppgreplay'],
    include_package_data=True,
    platforms='any',
    test_suite='gcppgreplay.test.test_main',
    classifiers=[
        'Programming Language :: Python',
        'Development Status :: 4 - Beta',
        'Natural Language :: English',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Software Development :: Libraries :: Application Frameworks',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
    ],
    extras_require={
        'testing': ['pytest'],
    }
)
