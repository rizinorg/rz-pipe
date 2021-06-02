#!/usr/bin/env python3
from setuptools import setup
import rzpipe


def readme():
    with open("README.md") as readme_file:
        return readme_file.read()


setup(
    name="rzpipe",
    version=rzpipe.version(),
    description="Pipe interface for rizin",
    long_description=readme(),
    long_description_content_type="text/markdown",
    author="rizinorg",
    author_email="info@rizin.re",
    url="https://rizin.re",
    license="MIT",
    package_dir={"rzpipe": "rzpipe"},
    packages=["rzpipe"],
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Software Development :: Assemblers",
        "Topic :: Software Development :: Debuggers",
        "Topic :: Software Development :: Disassemblers",
    ],
)
