#!/usr/bin/env python
# -*- coding: utf-8 -*-

# SPDX-License-Identifier: MIT
# Copyright (c)  Jannis Gebauer and others
# Originally from https://github.com/pyupio/dparse/
# Now maintained at https://github.com/aboutcode-org/dparse2


import pytest

from dparse2 import parse
from dparse2 import parser
from dparse2.dependencies import Dependency
from dparse2.dependencies import DependencyFile
from dparse2.dependencies import UnknownDependencyFileError


def test_dependency_serialize():
    dep = Dependency(name="foo", specs=(), line="foo==1.2.3")

    serialized = dep.serialize()
    assert dep.name == serialized["name"]
    assert dep.specs == serialized["specs"]
    assert dep.line == serialized["line"]

    dep.extras = "some-extras"
    dep.hashes = {"method": "sha256", "hash": "the hash"}
    dep.dependency_type = "requirements.txt"

    serialized = dep.serialize()
    assert dep.extras == serialized["extras"]
    assert dep.hashes == serialized["hashes"]
    assert dep.dependency_type == serialized["dependency_type"]


def test_dependency_deserialize():
    d = {"name": "foo", "specs": [], "line": "foo==1.2.3"}

    dep = Dependency.deserialize(d)

    assert d["name"] == dep.name
    assert d["specs"] == dep.specs
    assert d["line"] == dep.line

    d["extras"] = "some-extras"
    d["hashes"] = {"method": "sha256", "hash": "the hash"}
    d["dependency_type"] = "requirements.txt"

    dep = Dependency.deserialize(d)

    assert d["extras"] == dep.extras
    assert d["hashes"] == dep.hashes
    assert d["dependency_type"] == dep.dependency_type


def test_parser_class():
    dep_file = parse("", file_name="tox.ini")
    assert isinstance(dep_file.parser, parser.ToxINIParser)

    dep_file = parse("", path="tox.ini")
    assert isinstance(dep_file.parser, parser.ToxINIParser)

    dep_file = parse("", file_name="conda.yml")
    assert isinstance(dep_file.parser, parser.CondaYMLParser)

    dep_file = parse("", path="conda.yml")
    assert isinstance(dep_file.parser, parser.CondaYMLParser)

    dep_file = parse("", parser=parser.CondaYMLParser)
    assert isinstance(dep_file.parser, parser.CondaYMLParser)

    with pytest.raises(UnknownDependencyFileError):
        parse("")
