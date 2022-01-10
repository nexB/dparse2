# -*- coding: utf-8 -*-

# SPDX-License-Identifier: MIT
# Copyright (c)  Jannis Gebauer and others
# Originally from https://github.com/pyupio/dparse/
# Now maintained at https://github.com/nexB/dparse2

import json


class UnknownDependencyFileError(Exception):
    pass


class Dependency(object):

    def __init__(
        self,
        name,
        specs,
        line,
        source="pypi",
        meta={},
        extras=[],
        line_numbers=None,
        index_server=None,
        hashes=(),
        dependency_type=None,
        section=None,
    ):
        self.name = name
        self.key = name.lower().replace("_", "-")
        self.specs = specs
        self.line = line
        self.source = source
        self.meta = meta
        self.line_numbers = line_numbers
        self.index_server = index_server
        self.hashes = hashes
        self.dependency_type = dependency_type
        self.extras = extras
        self.section = section

    def __str__(self):  # pragma: no cover
        return "Dependency({name}, {specs}, {line})".format(
            name=self.name, specs=self.specs, line=self.line
        )

    def serialize(self):
        return {
            "name": self.name,
            "specs": self.specs,
            "line": self.line,
            "source": self.source,
            "meta": self.meta,
            "line_numbers": self.line_numbers,
            "index_server": self.index_server,
            "hashes": self.hashes,
            "dependency_type": self.dependency_type,
            "extras": self.extras,
            "section": self.section,
        }

    @classmethod
    def deserialize(cls, d):
        return cls(**d)

    @property
    def full_name(self):
        if self.extras:
            return "{}[{}]".format(self.name, ",".join(self.extras))
        return self.name


class DependencyFile(object):

    def __init__(
        self,
        content,
        path=None,
        sha=None,
        file_type=None,
        marker=((), ()),
        parser=None,
    ):
        self.content = content
        self.file_type = file_type
        self.path = path
        self.sha = sha
        self.marker = marker

        self.dependencies = []
        self.resolved_files = []
        self.is_valid = False
        self.file_marker, self.line_marker = marker

        if not parser:
            from dparse import parser as parser_class

            parsers_by_filetype = {
                "requirements.txt": parser_class.RequirementsTXTParser,
                "requirements.in": parser_class.RequirementsTXTParser,
                "tox.ini": parser_class.ToxINIParser,
                "conda.yml": parser_class.CondaYMLParser,
                "Pipfile": parser_class.PipfileParser,
                "Pipfile.lock": parser_class.PipfileLockParser,
                "setup.cfg": parser_class.SetupCfgParser,
            }

            parser = parsers_by_filetype.get(file_type)

            parsers_by_file_end = {
                (".txt", ".in"): parser_class.RequirementsTXTParser,
                ".yml": parser_class.CondaYMLParser,
                ".ini": parser_class.ToxINIParser,
                "Pipfile": parser_class.PipfileParser,
                "Pipfile.lock": parser_class.PipfileLockParser,
                "setup.cfg": parser_class.SetupCfgParser,
            }

            if not parser and path:
                for ends, prsr in parsers_by_file_end.items():
                    if path.endswith(ends):
                        parser = prsr
                        break
        if parser:
            self.parser = parser
        else:
            raise UnknownDependencyFileError

        self.parser = self.parser(self)

    def serialize(self):
        return {
            "file_type": self.file_type,
            "content": self.content,
            "path": self.path,
            "sha": self.sha,
            "dependencies": [dep.serialize() for dep in self.dependencies],
        }

    @classmethod
    def deserialize(cls, d):
        dependencies = [
            Dependency.deserialize(dep) for dep in d.pop("dependencies", [])
        ]
        instance = cls(**d)
        instance.dependencies = dependencies
        return instance

    def json(self):  # pragma: no cover
        return json.dumps(self.serialize(), indent=2)

    def parse(self):
        if self.parser.is_marked_file:
            self.is_valid = False
            return self

        self.parser.parse()
        self.is_valid = self.dependencies or self.resolved_files
        return self
