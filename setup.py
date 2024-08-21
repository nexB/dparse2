#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""The setup script."""

from setuptools import find_packages, setup

with open("README.rst") as readme_file:
    readme = readme_file.read()

with open("CHANGELOG.rst") as history_file:
    history = history_file.read()

setup(
    name="dparse2",
    version="0.7.0",
    description="A parser for Python dependency files",
    long_description=readme + "\n\n" + history,
    long_description_content_type="text/x-rst",
    author="originally from Jannis Gebauer, maintained by AboutCode.org",
    author_email="info@nexb.com",
    url="https://github.com/aboutcode-org/dparse2",
    packages=find_packages(include=["dparse2"]),
    include_package_data=True,
    install_requires=[
        "packvers",
        "pyyaml",
        "toml",
    ],
    license="MIT",
    zip_safe=False,
    keywords="dparse pypi dependencies tox conda pipfile setup.cfg",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.6",
    extras_require={
        "pipenv": ["pipenv"],
    },
)
