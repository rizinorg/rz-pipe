#!/usr/bin/env python3
from distutils.core import setup
import rzpipe

# with open('README.rst') as readme_file:
#    readme = readme_file.read()

setup(
    name="rzpipe",
    version=rzpipe.version(),
    license="MIT",
    description="Pipe interface for rizin",
    author="pancake",
    author_email="pancake@nopcode.org",
    url="https://rada.re",
    package_dir={"rzpipe": "rzpipe"},
    packages=["rzpipe"],
)
