#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
#
# Lookup tool for the kernel CODEOWNERS file: given file path(s), print
# the committers (owners) responsible for them.
#
# Evaluation rules follow the GitCode semantics described in the header
# of the CODEOWNERS file itself:
#   - Each line is a path pattern followed by its owners.
#   - The last matching rule wins; rules are ordered parent before child,
#     so the deepest matching path decides the owner.
#   - A trailing slash covers everything inside a directory.
#   - A '*' in a pattern matches any characters except '/'.
#   - The leading '* rule is the fallback for the whole tree.
#   - @UNMAINTAINED marks paths without a dedicated maintainer.
#
# Usage:
#   scripts/get_codeowner.py mm/highmem.c
#   scripts/get_codeowner.py -a arch/arm/boot/dts/aspeed-bmc-amd-ethanolx.dts
#   scripts/get_codeowner.py -p 0001-mm-fix-foo.patch
#   scripts/get_codeowner.py -p 000*.patch
#
# Paths are interpreted relative to the repository root; a relative path
# that exists in the current directory is resolved against it first, so
# the script also works when run from inside a subdirectory.
#
# With --patch, the touched files are taken from the diff headers of git
# format-patch / git diff files (or plain unified diffs), looked up one
# by one, and the union of the owners is printed at the end.  Every
# PATCH argument may also be a shell wildcard pattern such as '*.patch'
# to check a whole patch series at once; '-' reads a single patch from
# standard input.

import argparse
import glob
import os
import re
import subprocess
import sys

UNMAINTAINED = '@UNMAINTAINED'


class Rule:
    """One CODEOWNERS rule: a path pattern plus its owners."""

    def __init__(self, lineno, pattern, owners):
        self.lineno = lineno
        self.pattern = pattern
        self.owners = owners
        self.is_dir = pattern.endswith('/')
        self.regex = None
        body = pattern.rstrip('/')
        if body == '*':
            # The bare '* rule is the fallback for the whole tree.
            self.regex = re.compile(r'.*')
        elif '*' in pattern:
            # '*' matches any characters except '/'; anchor to the root.
            parts = body.lstrip('/').split('*')
            regex = '/' + '[^/]*'.join(re.escape(p) for p in parts)
            if self.is_dir:
                # A wildcard directory pattern also covers its contents.
                regex += '(/.*)?'
            self.regex = re.compile(regex)

    def matches(self, path):
        if self.regex:
            return self.regex.fullmatch(path) is not None
        if self.is_dir:
            return path == self.pattern.rstrip('/') or path.startswith(self.pattern)
        return path == self.pattern

    def __str__(self):
        return '%s (line %d)' % (self.pattern, self.lineno)


def parse_codeowners(path):
    """Parse a CODEOWNERS file into an ordered list of Rules."""
    rules = []
    with open(path, encoding='utf-8') as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            tokens = line.split()
            rules.append(Rule(lineno, tokens[0], tokens[1:]))
    return rules


def find_repo_root(codeowners_file):
    """Return the directory containing the CODEOWNERS file."""
    return os.path.normpath(os.path.dirname(os.path.abspath(codeowners_file)))


def normalize_path(arg, root):
    """Turn a command line argument into a repo-root-anchored '/path'."""
    def in_repo(path):
        return path == root or path.startswith(root + os.sep)

    if os.path.isabs(arg):
        # Absolute path: relativize to the repo root if inside it.
        real = os.path.normpath(arg)
        if in_repo(real):
            arg = os.path.relpath(real, root)
        else:
            arg = arg.lstrip('/')
    elif os.path.exists(arg):
        # A path that exists relative to the current directory refers to
        # that file, so queries work from inside a subdirectory too.
        real = os.path.normpath(os.path.join(os.getcwd(), arg))
        if in_repo(real):
            arg = os.path.relpath(real, root)

    path = os.path.normpath(arg).replace(os.sep, '/')
    if not path.startswith('/'):
        path = '/' + path
    return path


def lookup(rules, path):
    """Return every rule matching path, in file order (last one wins)."""
    return [r for r in rules if r.matches(path)]


def add_path(files, name):
    """Append a diff path to files, skipping empties and duplicates."""
    if name and name not in files:
        files.append(name)


def strip_diff_path(name):
    """Clean up a path from a '---'/'+++' diff header line."""
    name = name.split('\t')[0].strip().strip('"')
    if name.startswith('a/') or name.startswith('b/'):
        name = name[2:]
    return name


def parse_patch(patch):
    """Extract the file paths touched by a patch, in diff order.

    The 'diff --git a/... b/...' headers are preferred, as they also
    cover renames, mode changes and binary files, which carry no '+++'
    line; plain non-git diffs fall back to their '---'/'+++' headers.
    """
    if patch == '-':
        lines = sys.stdin.readlines()
    else:
        try:
            with open(patch, encoding='utf-8', errors='replace') as f:
                lines = f.readlines()
        except OSError as e:
            sys.exit('error: cannot read %s: %s' % (patch, e))

    files = []
    for line in lines:
        m = re.match(r'diff --git a/(.*) b/(.*)$', line.rstrip('\r\n'))
        if m:
            old, new = m.groups()
            add_path(files, new if new != '/dev/null' else old)
    if files:
        return files

    # No git headers: plain unified diff, take the paths from the
    # '---'/'+++' pairs; a deletion shows /dev/null on the '+++' side.
    old_path = None
    for line in lines:
        if line.startswith('--- '):
            old_path = strip_diff_path(line[4:])
        elif line.startswith('+++ '):
            new_path = strip_diff_path(line[4:])
            add_path(files, new_path if new_path != '/dev/null' else old_path)
    return files


def expand_patches(patterns):
    """Turn --patch arguments into a deduplicated list of patch files.

    Each argument may name a single patch or use shell wildcards, e.g.
    '*.patch', expanded in sorted order; '-' (standard input) is passed
    through and cannot be combined with other patches.
    """
    if '-' in patterns and len(patterns) > 1:
        sys.exit("error: '-' (standard input) cannot be combined with other patches")
    patches = []
    for pattern in patterns:
        if pattern != '-' and any(c in pattern for c in '*?['):
            matches = sorted(glob.glob(pattern))
            if not matches:
                sys.exit("error: no patch files match '%s'" % pattern)
            for match in matches:
                if match not in patches:
                    patches.append(match)
        elif pattern not in patches:
            patches.append(pattern)
    return patches


def report_path(rules, path, show_all):
    """Print the owners for one path.

    Returns the winning rule's owner list, [] for @UNMAINTAINED paths,
    or None when no rule matches at all.
    """
    matches = lookup(rules, path)
    if not matches:
        print('%s: no matching rule' % path)
        return None

    winner = matches[-1]
    if show_all:
        for r in matches:
            mark = '=>' if r is winner else '  '
            print('  %s %-12s %s' % (mark, ' '.join(r.owners), r))
    if winner.owners == [UNMAINTAINED]:
        print('%s: %s (no dedicated maintainer)' % (path, UNMAINTAINED))
        return []
    print('%s: %s' % (path, ' '.join(winner.owners)))
    return winner.owners


def report_patch(rules, patches, show_all):
    """Print the owners of the files each patch touches, then their union."""
    owners = []
    status = 0
    many = len(patches) > 1
    section = False
    for patch in patches:
        files = parse_patch(patch)
        if not files:
            if not many:
                sys.exit('error: no file diffs found in %s' % patch)
            if section:
                print()
            section = True
            print('%s: no file diffs, skipping' % patch)
            continue
        if many:
            if section:
                print()
            section = True
            print('%s:' % patch)
        for name in files:
            # Paths inside a patch are relative to the repository root.
            result = report_path(rules, '/' + name.lstrip('/'), show_all)
            if result is None:
                status = 1
            else:
                for owner in result:
                    if owner not in owners:
                        owners.append(owner)
    print('\nOwners: %s' % (' '.join(owners) if owners else '(none)'))
    return status


def main():
    repo_root = subprocess.run(
        ['git', 'rev-parse', '--show-toplevel'], capture_output=True,
        text=True).stdout.strip()
    default_file = os.path.join(repo_root, 'CODEOWNERS') if repo_root \
        else os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          'CODEOWNERS')

    parser = argparse.ArgumentParser(
        description='Look up the committers (CODEOWNERS owners) for given '
                    'file paths, or for every file a patch touches.')
    parser.add_argument('paths', nargs='*', metavar='PATH',
                        help='file path, relative to the repository root '
                             'or to the current directory')
    parser.add_argument('-f', '--codeowners', default=default_file,
                        help='path to the CODEOWNERS file (default: %(default)s)')
    parser.add_argument('-a', '--all', action='store_true',
                        help='show every matching rule, not just the winner')
    parser.add_argument('-p', '--patch', nargs='+', metavar='PATCH',
                        help='look up the owners of every file the given '
                             'patch(es) touch and print the union of them; '
                             'PATCH may be a wildcard pattern such as '
                             '"*.patch" ("-" reads one patch from standard '
                             'input)')
    args = parser.parse_args()

    if not args.paths and not args.patch:
        parser.error('nothing to look up: give PATH(s) or --patch PATCH')

    try:
        rules = parse_codeowners(args.codeowners)
    except OSError as e:
        sys.exit('error: cannot read %s: %s' % (args.codeowners, e))

    root = find_repo_root(args.codeowners)

    if args.patch:
        return report_patch(rules, expand_patches(args.patch), args.all)

    status = 0
    for arg in args.paths:
        if report_path(rules, normalize_path(arg, root), args.all) is None:
            status = 1
    return status


if __name__ == '__main__':
    sys.exit(main())
