# -*- coding: utf-8 -*-

# SPDX-License-Identifier: MIT
# Copyright (c)  Jannis Gebauer and others
# Originally from https://github.com/pyupio/dparse/
# Now maintained at https://github.com/nexB/dparse2

import json
import re
from collections import OrderedDict
from configparser import ConfigParser
from configparser import NoOptionError
from io import StringIO

import toml
import yaml

from packaging.requirements import InvalidRequirement
from packaging.requirements import Requirement as PackagingRequirement
from packaging.specifiers import SpecifierSet

from dparse.dependencies import Dependency, DependencyFile


# this is a backport from setuptools 26.1
def setuptools_parse_requirements_backport(strs):  # pragma: no cover
    # Copyright (C) 2016 Jason R Coombs <jaraco@jaraco.com>
    #
    # Permission is hereby granted, free of charge, to any person obtaining a
    # copy of this software and associated documentation files (the "Software"),
    # to deal in the Software without restriction, including without limitation
    # the rights to use, copy, modify, merge, publish, distribute, sublicense,
    # and/or sell copies of the Software, and to permit persons to whom the
    # Software is furnished to do so, subject to the following conditions:
    #
    # The above copyright notice and this permission notice shall be included in
    # all copies or substantial portions of the Software.
    #
    # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    # IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    # FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
    # THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    # LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
    # FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
    # DEALINGS IN THE SOFTWARE.

    """
    Yield ``Requirement`` objects for each specification in `strs`
    `strs` must be a string, or a (possibly-nested) iterable thereof.
    """

    # create a steppable iterator, so we can handle \-continuations
    def yield_lines(strs):
        """Yield non-empty/non-comment lines of a string or sequence"""
        if isinstance(strs, str):
            for s in strs.splitlines():
                s = s.strip()
                # skip blank lines/comments
                if s and not s.startswith("#"):
                    yield s
        else:
            for ss in strs:
                for s in yield_lines(ss):
                    yield s

    lines = iter(yield_lines(strs))

    for line in lines:
        # Drop comments -- a hash without a space may be in a URL.
        if " #" in line:
            line = line[: line.find(" #")]
        # If there is a line continuation, drop it, and append the next line.
        if line.endswith("\\"):
            line = line[:-2].strip()
            line += next(lines)
        yield PackagingRequirement(line)


class RequirementsTXTLineParser(object):

    @classmethod
    def parse(cls, line):
        try:
            # setuptools requires a space before the comment. If this isn't the
            # case, add it.
            if "\t#" in line:
                (parsed,) = setuptools_parse_requirements_backport(
                    line.replace("\t#", "\t #")
                )
            else:
                (parsed,) = setuptools_parse_requirements_backport(line)
        except InvalidRequirement:
            return None
        dep = Dependency(
            name=parsed.name,
            specs=parsed.specifier,
            line=line,
            extras=parsed.extras,
            dependency_type="requirements.txt",
        )
        return dep


class Parser(object):

    def __init__(self, obj):
        self.obj = obj
        self._lines = None

    def iter_lines(self, lineno=0):
        for line in self.lines[lineno:]:
            yield line

    @property
    def lines(self):
        if self._lines is None:
            self._lines = self.obj.content.splitlines()
        return self._lines

    @property
    def is_marked_file(self):
        for n, line in enumerate(self.iter_lines()):
            for marker in self.obj.file_marker:
                if marker in line:
                    return True
            if n >= 2:
                break
        return False

    def is_marked_line(self, line):
        for marker in self.obj.line_marker:
            if marker in line:
                return True
        return False

    @classmethod
    def parse_hashes(cls, line):
        HASH_REGEX = r"--hash[=| ][\w]+:[\w]+"
        hashes = []
        for match in re.finditer(HASH_REGEX, line):
            hashes.append(line[match.start() : match.end()])
        return re.sub(HASH_REGEX, "", line).strip(), hashes

    @classmethod
    def parse_index_server(cls, line):
        """
        Return an inder server URL given a text ``line`` or None
        """
        # this file is using a private index server, try to parse it
        if "=" in line:
            splitter = "="
        elif " " in line:
            splitter = " "
        else:
            return

        _option, _, index_server = line.partition(splitter)

        if " #" in index_server:
            index_server, _, _ = index_server.rpartition("#")
            index_server = index_server.strip()

        index_server = index_server.rstrip("/") + "/"
        return index_server

    @classmethod
    def resolve_file(cls, file_path, line):
        line = line.replace("--requirement ", "").replace("-r ", "")
        if " #" in line:
            line = line.split("#")[0].strip()

        if "/" not in file_path:
            return line

        parts = file_path.split("/")
        return "/".join(parts[:-1]) + "/" + line


class RequirementsTXTParser(Parser):

    def parse(self):
        """
        Parses a requirements.txt-like file
        """
        index_server = None
        for num, line in enumerate(self.iter_lines()):
            line = " ".join(line.split())
            if not line:
                continue

            if line.startswith("#"):
                # comments are lines that start with # only
                continue

            if line.startswith(("-i", "--index-url", "--extra-index-url")):
                # this file is using a private index server, try to parse it
                index_server = Parser.parse_index_server(line)
                continue

            elif self.obj.path and (
                line.startswith("-r") or line.startswith("--requirement")
            ):
                self.obj.resolved_files.append(self.resolve_file(self.obj.path, line))
            elif line.startswith(
                (
                    "-f",
                    "--find-links",
                    "--no-index",
                    "--allow-external",
                    "--allow-unverified",
                    "-Z",
                    "--always-unzip",
                )
            ):
                continue

            elif self.is_marked_line(line):
                continue

            else:
                try:

                    parseable_line = line

                    # multiline requirements are not parseable
                    if "\\" in line:
                        parseable_line = line.replace("\\", "")
                        for next_line in self.iter_lines(num + 1):
                            parseable_line += next_line.strip().replace("\\", "")
                            line += "\n" + next_line
                            if "\\" in next_line:
                                continue
                            break
                        # ignore multiline requirements if they are marked
                        if self.is_marked_line(parseable_line):
                            continue

                    hashes = []
                    if "--hash" in parseable_line:
                        parseable_line, hashes = Parser.parse_hashes(parseable_line)

                    req = RequirementsTXTLineParser.parse(parseable_line)
                    if req:
                        req.hashes = hashes
                        req.index_server = index_server
                        # replace the requirements line with the 'real' line
                        req.line = line
                        self.obj.dependencies.append(req)
                except ValueError:
                    continue


class ToxINIParser(Parser):

    def parse(self):
        parser = ConfigParser()
        parser.read_file(StringIO(self.obj.content))
        for section in parser.sections():
            try:
                content = parser.get(section=section, option="deps")
                for line in content.splitlines():
                    if self.is_marked_line(line):
                        continue
                    if not line:
                        continue
                    req = RequirementsTXTLineParser.parse(line)
                    if req:
                        req.dependency_type = self.obj.file_type
                        self.obj.dependencies.append(req)

            except NoOptionError:
                pass


class CondaYMLParser(Parser):

    def parse(self):
        try:
            data = yaml.safe_load(self.obj.content) or {}
            dependencies = data.get("dependencies") or []
            for dep in dependencies:
                if not isinstance(dep, dict):
                    continue
                lines = dep.get("pip") or []
                for line in lines:
                    if self.is_marked_line(line):
                        continue
                    req = RequirementsTXTLineParser.parse(line)
                    if req:
                        req.dependency_type = self.obj.file_type
                        self.obj.dependencies.append(req)
        except yaml.YAMLError:
            pass


class PipfileParser(Parser):

    def parse(self):
        """
        Parse a Pipfile (as seen in pipenv)
        """
        try:
            data = toml.loads(self.obj.content, _dict=OrderedDict)
            if not data:
                return
            for package_type in ["packages", "dev-packages"]:
                if package_type not in data:
                    continue

                for name, specs in data[package_type].items():
                    # skip on VCS dependencies
                    if not isinstance(specs, str):
                        continue
                    if specs == "*":
                        specs = ""

                    self.obj.dependencies.append(
                        Dependency(
                            name=name,
                            specs=SpecifierSet(specs),
                            dependency_type="Pipfile",
                            line="".join([name, specs]),
                            section=package_type,
                        )
                    )
        except (toml.TomlDecodeError, IndexError):
            pass


class PipfileLockParser(Parser):

    def parse(self):
        """
        Parse a Pipfile.lock (as seen in pipenv)
        """
        try:
            data = json.loads(self.obj.content, object_pairs_hook=OrderedDict)
            if not data:
                return
            for package_type in ["default", "develop"]:
                if not package_type in data:
                    continue
                for name, meta in data[package_type].items():
                    # skip VCS dependencies
                    if "version" not in meta:
                        continue
                    specs = meta["version"]
                    hashes = meta["hashes"]
                    self.obj.dependencies.append(
                        Dependency(
                            name=name,
                            specs=SpecifierSet(specs),
                            dependency_type="Pipfile.lock",
                            hashes=hashes,
                            line="".join([name, specs]),
                            section=package_type,
                        )
                    )
        except ValueError:
            pass


class SetupCfgParser(Parser):

    def parse(self):
        parser = ConfigParser()
        parser.readfp(StringIO(self.obj.content))
        for section in parser.values():
            if section.name == "options":
                options = "install_requires", "setup_requires", "test_require"
                for name in options:
                    content = section.get(name)
                    if not content:
                        continue
                    self._parse_content(content)
            elif section.name == "options.extras_require":
                for content in section.values():
                    self._parse_content(content)

    def _parse_content(self, content):
        for line in content.splitlines():
            if self.is_marked_line(line):
                continue
            if not line:
                continue
            req = RequirementsTXTLineParser.parse(line)
            if req:
                req.dependency_type = self.obj.file_type
                self.obj.dependencies.append(req)


def parse(content, file_type=None, path=None, sha=None, marker=((), ()), parser=None):
    dep_file = DependencyFile(
        content=content,
        path=path,
        sha=sha,
        marker=marker,
        file_type=file_type,
        parser=parser,
    )

    return dep_file.parse()
