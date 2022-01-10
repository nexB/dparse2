#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""The setup script."""

from setuptools import setup, find_packages

with open('README.rst') as readme_file:
    readme = readme_file.read()

with open('HISTORY.rst') as history_file:
    history = history_file.read()


setup(
    name='dparse2',
    version='0.6.0',
    description="A parser for Python dependency files",
    long_description=readme + '\n\n' + history,
    author="originally from Jannis Gebauer, maintained by AboutCode.org",
    author_email='info@nexb.com',
    url='https://github.com/nexB/dparse2',
    packages=find_packages(include=['dparse']),
    include_package_data=True,
    install_requires= [
        "packaging",
        "pyyaml",
        "toml",
    ],
    license="MIT",
    zip_safe=False,
    keywords='dparse pypi dependencies setup.py pipfile requirements',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
    ],
    python_requires=">=3.6",
    extras_require={
        'pipenv':  ["pipenv"],
    }
)
